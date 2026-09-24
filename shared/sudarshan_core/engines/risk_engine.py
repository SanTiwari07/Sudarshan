# backend/app/engines/risk_engine.py
"""
Sudarshan Deterministic Risk Engine
======================================
Implements the full Fraud Risk Score (FRS) formula from the Sudarshan proposal:

  FRS = 0.25 × STEI + 0.35 × Dynamic + 0.20 × Correlation + 0.20 × BankingImpact

STEI - 5-axis formula (PDF spec):
  STEI = 0.60 × CT  +  0.20 × BT  +  0.10 × PR  +  0.05 × OB  +  0.05 × IR

  Where:
    CT - Credential Theft axis       (accessibility + SMS + overlay signals)
    BT - Banking Targeting axis      (Indian bank package matches)
    PR - Permission Risk axis        (dangerous permission set size)
    OB - Obfuscation axis            (DexClassLoader + reflection + entropy)
    IR - Infrastructure Risk axis    (hardcoded URLs / IPs)

All components are normalized to 0–100 before applying weights.
Final score is capped at 100.
"""

import logging
import math
from typing import Any, Dict, List, Optional, Tuple

from sudarshan_core.engines.execution_assertions import (
    INCOMPLETE_EXERCISE_CONFIDENCE_PENALTY,
    VERDICT_INCOMPLETE_EXERCISE,
    build_execution_assertions,
)

logger = logging.getLogger(__name__)

# ─── Malware Family Severity Weights ─────────────────────────────────────────

FAMILY_BANKING_WEIGHT: Dict[str, float] = {
    "Drinik":    1.0,   # Primary Indian banking trojan - full weight
    "Xenomorph": 1.0,   # ATS-enabled, 400+ bank targets
    "Cerberus":  1.0,   # Full overlay + RAT
    "Anubis":    0.9,
    "Hydra":     0.85,
    "SpyNote":   0.8,
    "Joker":     0.6,
    "SOVA":      1.0,
    "FluBot":    0.9,
    "Unknown":   0.5,
}

# ─── STEI - 5-Axis Formula (PDF Spec) ────────────────────────────────────────

def _axis_ct(flags: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Credential Theft axis (weight 0.60).
    Captures the three primary credential-harvesting attack vectors.
    Score: 0–100.
    """
    evidence: List[str] = []
    score = 0.0

    # Accessibility service - OTP tap injection and screen scraping
    if flags.get("has_accessibility_abuse"):
        score += 40.0
        evidence.append("BIND_ACCESSIBILITY_SERVICE: screen-scraping / tap-injection vector (+40 CT)")

    # SMS interception - OTP theft
    if flags.get("has_sms_read_write"):
        score += 35.0
        evidence.append("READ/RECEIVE_SMS: OTP interception via SMS (+35 CT)")

    # Overlay windows - fake login phishing
    if flags.get("has_system_alert_window"):
        score += 25.0
        evidence.append("SYSTEM_ALERT_WINDOW: phishing overlay capability (+25 CT)")

    return min(score, 100.0), evidence


def _axis_bt(flags: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Banking Targeting axis (weight 0.20).
    Score driven by number of matched Indian banking app package names.
    Score: 0–100.
    """
    evidence: List[str] = []
    bank_pkgs = flags.get("indian_bank_packages_found", [])
    score = 0.0

    if flags.get("visual_impersonation_detected"):
        conf = float(flags.get("visual_impersonation_confidence") or 0.0)
        inst = flags.get("visual_impersonation_institution") or "protected institution"
        boost = min(35.0 + conf * 40.0, 85.0)
        score = max(score, boost)
        evidence.append(
            f"VIDE-F001: visual impersonation of {inst} (confidence {conf:.2f}, +{boost:.0f} BT)"
        )

    if not flags.get("targets_indian_banks") and not bank_pkgs:
        if score > 0:
            return min(score, 100.0), evidence
        return 0.0, evidence

    # Base 20 for any targeting, +10 per additional package up to 100
    pkg_score = 20.0 + min(len(bank_pkgs) * 10.0, 80.0)
    score = max(score, pkg_score)
    evidence.append(
        f"{len(bank_pkgs)} Indian banking package(s) matched: "
        f"{', '.join(bank_pkgs[:3])} (+{pkg_score:.0f} BT)"
    )
    return min(score, 100.0), evidence


def _axis_pr(flags: Dict[str, Any], all_permissions: Optional[List[str]] = None) -> Tuple[float, List[str]]:
    """
    Permission Risk axis (weight 0.10).
    Counts dangerous permissions declared in the manifest.
    Score: 0–100.
    """
    DANGEROUS_PERMS = {
        "BIND_ACCESSIBILITY_SERVICE": 20,
        "READ_SMS": 18, "RECEIVE_SMS": 18, "SEND_SMS": 12,
        "SYSTEM_ALERT_WINDOW": 15,
        "REQUEST_INSTALL_PACKAGES": 20,
        "READ_CONTACTS": 8, "WRITE_CONTACTS": 10,
        "READ_CALL_LOG": 10, "PROCESS_OUTGOING_CALLS": 10,
        "RECORD_AUDIO": 8, "CAMERA": 8,
        "ACCESS_FINE_LOCATION": 10,
        "GET_TASKS": 8,
        "RECEIVE_BOOT_COMPLETED": 6,
        "KILL_BACKGROUND_PROCESSES": 6,
    }
    evidence: List[str] = []
    score = 0.0
    perms = all_permissions or []

    for perm in perms:
        short = perm.split(".")[-1]
        w = DANGEROUS_PERMS.get(short, 0)
        if w:
            score += w
            evidence.append(f"{short}: +{w} PR")

    if score > 0:
        evidence = [f"{len([p for p in perms if p.split('.')[-1] in DANGEROUS_PERMS])} "
                    f"dangerous permission(s) (+{min(score, 100):.0f} PR)"]
    return min(score, 100.0), evidence


def _axis_ob(flags: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Obfuscation axis (weight 0.05).
    Measures code-hiding techniques: dynamic loading, reflection, native libs, entropy.
    Score: 0–100.
    """
    evidence: List[str] = []
    score = 0.0
    apis = flags.get("dangerous_apis_found", [])

    # Dynamic code loading (DexClassLoader / PathClassLoader)
    dex_apis = [a for a in apis if a in ("DexClassLoader", "PathClassLoader")]
    if dex_apis:
        score += 40.0
        evidence.append(f"{', '.join(dex_apis)}: dynamic DEX loading (+40 OB)")

    # Native library loading (.so files)
    if "System.loadLibrary" in apis:
        score += 20.0
        evidence.append("System.loadLibrary: native .so loading (+20 OB)")

    # Java reflection APIs
    if flags.get("has_reflection"):
        score += 25.0
        evidence.append("Class.forName / getDeclaredMethod / invoke: reflection detected (+25 OB)")

    # String pool entropy (0.0–1.0 ratio)
    entropy = flags.get("obfuscation_score", 0.0)
    if entropy > 0.5:
        e_contrib = round((entropy - 0.5) * 30.0, 1)  # max +15 at entropy=1.0
        score += e_contrib
        evidence.append(f"String entropy {entropy:.2f} → obfuscated strings (+{e_contrib:.1f} OB)")

    # Concealed payload - a nested APK/DEX or encrypted blob shipped as an asset.
    # Weighted highest in this axis because it defeats static analysis outright:
    # the manifest describes a stub, not the code that will actually run. Three
    # trojans in the labelled corpus (Anubis, Hook, Drinik) declared 4, 1 and 16
    # permissions respectively and scored below a file manager without this.
    if flags.get("has_concealed_payload"):
        score += 60.0
        for line in (flags.get("concealment_evidence") or [])[:3]:
            evidence.append(f"{line} (+60 OB)")
        if not flags.get("concealment_evidence"):
            evidence.append("Concealed executable payload detected (+60 OB)")

    return min(score, 100.0), evidence


def _axis_ir(flags: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Infrastructure Risk axis (weight 0.05).
    Counts hardcoded C2 URLs / IP addresses.
    Score: 0–100.
    """
    evidence: List[str] = []
    urls = flags.get("hardcoded_urls_ips", [])

    if not urls:
        return 0.0, evidence

    # Each URL = 10 points, capped at 100
    score = min(len(urls) * 10.0, 100.0)
    evidence.append(f"{len(urls)} hardcoded network indicator(s) (+{score:.0f} IR)")
    return score, evidence


def _calculate_stei(
    flags: Dict[str, Any],
    all_permissions: Optional[List[str]] = None,
) -> Tuple[float, Dict[str, float], List[str]]:
    """
    STEI = 0.60 × CT + 0.20 × BT + 0.10 × PR + 0.05 × OB + 0.05 × IR
    Returns (stei_score, axes_dict, evidence_list, evidence_by_axis).
    """
    ct, ct_ev = _axis_ct(flags)
    bt, bt_ev = _axis_bt(flags)
    pr, pr_ev = _axis_pr(flags, all_permissions)
    ob, ob_ev = _axis_ob(flags)
    ir, ir_ev = _axis_ir(flags)

    axes = {"ct": round(ct, 2), "bt": round(bt, 2), "pr": round(pr, 2),
            "ob": round(ob, 2), "ir": round(ir, 2)}

    all_evidence = ct_ev + bt_ev + pr_ev + ob_ev + ir_ev
    by_axis = {"ct": ct_ev, "bt": bt_ev, "pr": pr_ev, "ob": ob_ev, "ir": ir_ev}

    weights = {"ct": 0.60, "bt": 0.20, "pr": 0.10, "ob": 0.05, "ir": 0.05}

    # ── Blind axes are UNKNOWN, not zero ──────────────────────────────────────
    #
    # CT and BT are read entirely from the manifest and the string pool. When a
    # concealed payload is present, the manifest describes a stub and the real
    # code is a nested archive nobody has parsed - so a 0 on those axes means
    # "we could not see", not "there is nothing".
    #
    # Scoring it as 0 anyway inverts the metric for exactly the samples it
    # exists to catch. Measured on this emulator, with the real analyzer:
    #
    #   Anubis  (banking trojan, payload concealed) STEI  9.20  CT  0  IR  50
    #   NewPipe (video player, nothing concealed)   STEI 24.64  CT 25  IR 100
    #
    # The benign app scored higher, because it honestly declares
    # SYSTEM_ALERT_WINDOW for picture-in-picture and ships real endpoints,
    # while the trojan declares four permissions and hides the rest. An app
    # was being rewarded for disclosure and a trojan rewarded for concealment.
    #
    # This is the treatment the FRS axes already get one level up
    # ("an excluded axis is one with no data - it is not scored as benign"):
    # drop the blind axes and renormalise over the axes that still carry
    # evidence. It invents nothing - PR, OB and IR are still measured - it only
    # stops counting an unknown as an acquittal.
    #
    # Deliberately narrow: only axes that are BOTH visibility-dependent AND
    # actually zero are dropped. A concealed sample that still declares
    # accessibility has told us something real, and that evidence is kept.
    excluded: List[str] = []
    if flags.get("has_concealed_payload"):
        for name, value in (("ct", ct), ("bt", bt)):
            if value <= 0.0:
                excluded.append(name)

    scored = {k: v for k, v in weights.items() if k not in excluded}
    total_weight = sum(scored.values())
    if not scored or total_weight <= 0:
        # Every axis blind. Refuse to emit a number rather than emit 0.0, which
        # would read as "measured, and clean".
        excluded = []
        scored = weights
        total_weight = sum(weights.values())

    values = {"ct": ct, "bt": bt, "pr": pr, "ob": ob, "ir": ir}
    stei = sum(values[k] * (w / total_weight) for k, w in scored.items())
    stei = round(min(stei, 100.0), 2)

    if excluded:
        all_evidence.append(
            "STEI axes " + "/".join(a.upper() for a in excluded) +
            " could not be measured: the payload is concealed, so the manifest "
            "and string pool describe a stub rather than the code that runs. "
            "They are excluded rather than scored as zero."
        )
    axes["excluded"] = excluded
    # The renormalised weight each axis actually carried. The frontend ledger
    # reconstructs per-axis contributions from these; without them it has to
    # assume the nominal 0.60/0.20/0.10/0.05/0.05 split, which is wrong for
    # every sample where a blind axis was dropped and the rest renormalised.
    axes["weights_used"] = {k: round(w / total_weight, 4) for k, w in scored.items()}
    return stei, axes, all_evidence, by_axis


# ─── Threat Scenario Table ────────────────────────────────────────────────────

def build_threat_scenario_table(flags: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build the granular threat-scenario correlation table from the PDF.
    Each active flag maps to one or more named threat scenarios with per-vector risk ratings.

    Returns a list of ThreatScenarioRow-compatible dicts.
    """
    rows: List[Dict[str, Any]] = []

    if flags.get("has_accessibility_abuse"):
        rows.append({
            "indicator": "Accessibility Service",
            "threat_scenario": "OTP Harvesting via UI Scraping",
            "overlay_risk": "High",
            "credential_theft_risk": "Critical",
            "c2_risk": "Medium",
            "persistence_risk": "High",
            "evidence": "BIND_ACCESSIBILITY_SERVICE declared in manifest",
            "confidence": 92,
        })
        rows.append({
            "indicator": "Accessibility Service",
            "threat_scenario": "Tap Injection / ATS-style Automated Transfer",
            "overlay_risk": "Medium",
            "credential_theft_risk": "High",
            "c2_risk": "Low",
            "persistence_risk": "Medium",
            "evidence": "BIND_ACCESSIBILITY_SERVICE - enables programmatic tap injection",
            "confidence": 85,
        })

    if flags.get("has_sms_read_write"):
        rows.append({
            "indicator": "SMS Read/Write Permission",
            "threat_scenario": "OTP / 2FA Interception",
            "overlay_risk": "N/A",
            "credential_theft_risk": "Critical",
            "c2_risk": "Medium",
            "persistence_risk": "Low",
            "evidence": "READ_SMS / RECEIVE_SMS - bank OTP messages readable before user sees them",
            "confidence": 95,
        })

    if flags.get("has_system_alert_window"):
        rows.append({
            "indicator": "Overlay Window Capability",
            "threat_scenario": "Phishing Overlay - Fake Banking Login Screen",
            "overlay_risk": "Critical",
            "credential_theft_risk": "High",
            "c2_risk": "Low",
            "persistence_risk": "Medium",
            "evidence": "SYSTEM_ALERT_WINDOW - draws UI layer over any banking app",
            "confidence": 88,
        })

    if flags.get("targets_indian_banks"):
        pkgs = flags.get("indian_bank_packages_found", [])
        rows.append({
            "indicator": "Indian Banking App Targeting",
            "threat_scenario": "Targeted Overlay / Credential Theft Campaign",
            "overlay_risk": "High",
            "credential_theft_risk": "High",
            "c2_risk": "Medium",
            "persistence_risk": "Low",
            "evidence": f"Package names matched: {', '.join(pkgs[:3]) or 'see hardcoded strings'}",
            "confidence": 90,
        })

    apis = flags.get("dangerous_apis_found", [])

    if "DexClassLoader" in apis or "PathClassLoader" in apis:
        rows.append({
            "indicator": "Dynamic Code Loading",
            "threat_scenario": "Stage-2 Payload Drop - Evades Static Scanners",
            "overlay_risk": "Medium",
            "credential_theft_risk": "High",
            "c2_risk": "High",
            "persistence_risk": "High",
            "evidence": f"{'DexClassLoader' if 'DexClassLoader' in apis else 'PathClassLoader'} API usage detected",
            "confidence": 87,
        })

    if "addJavascriptInterface" in apis:
        rows.append({
            "indicator": "WebView JavaScript Bridge",
            "threat_scenario": "JavaScript-to-Native RCE via WebView",
            "overlay_risk": "Medium",
            "credential_theft_risk": "Critical",
            "c2_risk": "High",
            "persistence_risk": "Low",
            "evidence": "addJavascriptInterface exposes native methods to JavaScript",
            "confidence": 91,
        })

    if any(a in apis for a in ("Runtime.exec", "ProcessBuilder.start")):
        rows.append({
            "indicator": "Shell Command Execution",
            "threat_scenario": "OS Command Execution / Privilege Escalation",
            "overlay_risk": "Low",
            "credential_theft_risk": "Medium",
            "c2_risk": "High",
            "persistence_risk": "High",
            "evidence": f"{'Runtime.exec' if 'Runtime.exec' in apis else 'ProcessBuilder.start'} found",
            "confidence": 82,
        })

    if "System.loadLibrary" in apis:
        rows.append({
            "indicator": "Native Library Loading",
            "threat_scenario": "Native Code Execution - Bypasses Java Analysis",
            "overlay_risk": "Low",
            "credential_theft_risk": "Medium",
            "c2_risk": "Medium",
            "persistence_risk": "High",
            "evidence": "System.loadLibrary - loads .so native binary at runtime",
            "confidence": 78,
        })

    if flags.get("has_reflection"):
        rows.append({
            "indicator": "Java Reflection APIs",
            "threat_scenario": "Anti-Analysis / Hidden Class Invocation",
            "overlay_risk": "Low",
            "credential_theft_risk": "Medium",
            "c2_risk": "Medium",
            "persistence_risk": "Medium",
            "evidence": "Class.forName / getDeclaredMethod / invoke detected",
            "confidence": 74,
        })

    urls = flags.get("hardcoded_urls_ips", [])
    if urls:
        rows.append({
            "indicator": "Hardcoded C2 Infrastructure",
            "threat_scenario": "Command & Control Beaconing",
            "overlay_risk": "Low",
            "credential_theft_risk": "Medium",
            "c2_risk": "Critical",
            "persistence_risk": "Medium",
            "evidence": f"{len(urls)} hardcoded endpoint(s): {urls[0][:60]}{'…' if len(urls[0]) > 60 else ''}",
            "confidence": 80,
        })

    return rows


# ─── BFCI Weights (matches Sudarshan proposal) ────────────────────────────────

_BFCI_WEIGHTS = {
    "accessibility": 0.35,   # wa - present in 87% of banking trojans (ThreatFabric 2024)
    "sms":           0.25,   # ws - OTP interception
    "overlay":       0.20,   # wo - phishing overlay attacks
    "banking":       0.10,   # wb - confirms banking app targeting
    "network":       0.05,   # wn - C2 communication
    "persistence":   0.05,   # wp - device admin / lockdown
}


# ─── Dynamic Score ────────────────────────────────────────────────────────────

def _coerce_score(value: Any, field: str, lo: float = 0.0, hi: float = 100.0) -> float:
    """
    Validate one externally-supplied score at the trust boundary.

    The dynamic-analysis payload arrives as an untyped dict from the sandbox.
    Isolation of the verdict must rest on validation, not on the convention that
    the only current writer happens to behave. Anything non-numeric, NaN, inf or
    out of range is rejected to 0.0 with a warning rather than being propagated
    into a score.

    Valid inputs are returned unchanged, so no existing verdict shifts.
    """
    try:
        score = float(value)
    except (TypeError, ValueError):
        if value is not None:
            logger.warning(f"[RiskEngine] Non-numeric {field}={value!r} - treated as 0.0")
        return 0.0

    if not math.isfinite(score):
        logger.warning(f"[RiskEngine] Non-finite {field}={value!r} - treated as 0.0")
        return 0.0

    if score < lo or score > hi:
        logger.warning(f"[RiskEngine] {field}={score} outside [{lo}, {hi}] - clamped")
        return max(lo, min(score, hi))
    return score


def _validated_components(raw: Any) -> Dict[str, float]:
    """Return BFCI components with every value validated to [0, 100]."""
    if not isinstance(raw, dict):
        if raw:
            logger.warning(f"[RiskEngine] bfci_components is {type(raw).__name__}, expected dict")
        return {}
    return {
        str(key): _coerce_score(value, f"bfci_components[{key}]")
        for key, value in raw.items()
    }


def _calculate_bfci_from_frida(dynamic: Dict) -> Tuple[float, List[str]]:
    """
    Compute BFCI using the exact weighted formula from the Sudarshan proposal.
    Used when Frida sandbox has provided pre-computed component scores.

    BFCI = (wa × A) + (ws × S) + (wo × O) + (wb × B) + (wn × N) + (wp × P)
    """
    # Validate at the boundary - see _coerce_score. The sandbox is the only
    # current writer, but the verdict must not depend on that staying true.
    components = _validated_components(dynamic.get("bfci_components", {}))
    raw_evidence = dynamic.get("bfci_evidence", [])
    evidence: List[str] = list(raw_evidence) if isinstance(raw_evidence, list) else []

    reported_bfci = _coerce_score(dynamic.get("bfci", 0), "bfci")

    # If frida_sandbox.py already computed bfci, trust the validated value
    if reported_bfci > 0 and components:
        bfci = reported_bfci
        if not evidence:
            for key, weight in _BFCI_WEIGHTS.items():
                comp_score = components.get(key, 0.0)
                if comp_score > 0:
                    evidence.append(
                        f"BFCI[{key}]: {comp_score:.0f} × {weight} = +{weight * comp_score:.1f}"
                    )
        return round(min(bfci, 100.0), 2), evidence

    # Recompute from components if bfci field is missing
    bfci = sum(_BFCI_WEIGHTS.get(k, 0) * v for k, v in components.items())
    return round(min(bfci, 100.0), 2), evidence


# Minimum observable activity for a sandbox run to count as evidence about the
# sample rather than evidence about the sandbox.
_MIN_DYNAMIC_EVENTS = 1

# STEI at or above this is strong declared fraud capability: SMS interception,
# accessibility abuse, overlay, or a comparable combination. See the static
# evidence floor in calculate_risk_score for why it matters.
_STEI_STRONG = 50.0

# BFCI at or above this is treated as a substantive behavioural observation:
# enough to call a run conclusive on its own, and enough to accept that the
# sandbox actually saw a concealed payload deploy.
_BFCI_SUBSTANTIVE = 20.0

_OBSERVED_BEHAVIOR_FIELDS = (
    "api_calls",
    "network_logs",
    "activities_triggered",
    "files_accessed",
)

# Evidence categories the harness writes about ITSELF. A screenshot record proves
# the sandbox took a screenshot; it says nothing about what the sample did, so it
# must never satisfy the conclusiveness threshold.
_HARNESS_EVIDENCE_CATEGORIES = frozenset({
    "SCREENSHOT",
    "HARNESS",
    "HARNESS_ACTION",
    "DIAGNOSTIC",
})

# Hooks that describe something the HARNESS did, not something the sample did.
#
# The agent now files these under the `harness_action` category, but ten stored
# runs predate that split and still carry them under `anti_analysis`. Matching
# on the hook name as well keeps those runs scoring correctly instead of
# requiring a re-analysis of every case.
#
# `Build.<static fields>` is the whole reason this exists: the harness spoofs
# emulator-identifying Build fields at attach time on every emulator run, and
# emitted an evasion event about its own action. Every stored run carries
# exactly one - the same hook, for benign apps and trojans alike - and that one
# event excluded the dynamic axis on five banking trojans.
_HARNESS_ATTRIBUTED_HOOKS = frozenset({
    "Build.<static fields>",
    "sandbox.build_fields_spoofed",
})


def _is_harness_attributed(event: Any) -> bool:
    """True when an event describes the harness's own action, not the sample's."""
    if not isinstance(event, dict):
        return False
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    if str(event.get("actor") or data.get("actor") or "").lower() == "harness":
        return True
    if str(event.get("category") or data.get("category") or "").upper() == "HARNESS_ACTION":
        return True
    hook = event.get("hook") or data.get("hook") or ""
    return hook in _HARNESS_ATTRIBUTED_HOOKS


def sample_attributable_evasion(events: Any) -> List[Dict]:
    """
    The subset of evasion events the SAMPLE is responsible for.

    Evasion is a claim about the sample resisting observation. Anything the
    harness did to conceal itself is not evidence for that claim, and counting
    it as such inverts the meaning of the whole dynamic axis.
    """
    try:
        return [e for e in (events or []) if not _is_harness_attributed(e)]
    except TypeError:
        return []

# Evasion is the sample resisting observation, not the sample behaving. It is
# counted separately so an evasion-only run reads as "we were blocked", never as
# "we looked and found nothing".
_EVASION_EVIDENCE_CATEGORIES = frozenset({"ANTI_ANALYSIS"})

# Buckets that hold ORDINARY application behaviour, by their own definition:
# `app_telemetry` is "activity lifecycle, keyboard, generic crypto / prefs /
# windows" and `smoke` is "baseline runtime smoke-test events" (see
# frida_sandbox.collected_events).
#
# They are recorded as evidence but must not, on their own, establish that the
# sandbox meaningfully observed the sample - because every app produces them.
# _MIN_DYNAMIC_EVENTS is 1, so a single lifecycle event was enough to mark a run
# conclusive and score the fraud axis 0.0 at weight 0.35.
#
# Measured: Anubis fired four hooks in a 300s run - one UI accessibility
# dispatch, one harness action, two preference reads - reached 25% coverage,
# and that one telemetry event scored the fraud axis as a clean zero, costing
# 15 points (34.44 -> 19.38, out of the Suspicious band into Safe).
#
# This does NOT make the dynamic axis one-directional. A well-covered run that
# observes benign behaviour still lowers the verdict: api_calls, network_logs,
# activities_triggered and files_accessed are all still counted, and so is any
# fraud-category bucket. Only the two ordinary-behaviour buckets stop counting
# as proof that we looked.
_BASELINE_EVIDENCE_CATEGORIES = frozenset({"APP_TELEMETRY", "SMOKE"})

_DEFAULT_BASELINE_HOOK_NAMES = frozenset({
    "Application.onCreate",
    "Activity.onCreate",
    "Activity.onResume",
    "Activity.onPause",
    "Activity.onDestroy",
    "ContextWrapper.getSharedPreferences",
})

_INTERNAL_RUNTIME_FILE_PATTERNS = (
    "frida-",
    ".dex",
    ".vdex",
    ".odex",
    ".prof",
    "/oat/",
    "/code_cache/",
)


def _count_observed_sample_behavior(dynamic: Dict) -> int:
    """Count hook-derived sample behaviour items (not harness commentary)."""
    # Hook names already accounted for in a bucket that does not count as
    # observation. `api_calls` is a FLATTENED, uncategorised projection of the
    # same hook events, so without this the identical event is counted twice -
    # once categorised (and skipped) and once as a bare name (and counted).
    #
    # Measured on a live Anubis run: frida_events held exactly
    # {harness_action: 1, smoke: 1, app_telemetry: 1} and api_calls held
    # ["Activity.onResume", "ContextWrapper.getSharedPreferences"] - the same
    # two ordinary events. The bucket filter skipped them and api_calls let
    # them back in, so the run still read as conclusive.
    #
    # Subtracting by name rather than mapping names to categories: the result
    # already tells us which bucket each hook landed in, so no second table is
    # needed and none can drift.
    _discounted: set = set()
    _buckets = dynamic.get("frida_events")
    if isinstance(_buckets, dict):
        for _name, _events in _buckets.items():
            _upper = str(_name).upper()
            if not (
                _upper in _EVASION_EVIDENCE_CATEGORIES
                or _upper in _HARNESS_EVIDENCE_CATEGORIES
                or _upper in _BASELINE_EVIDENCE_CATEGORIES
            ):
                continue
            for _event in _events or []:
                if not isinstance(_event, dict):
                    continue
                _data = _event.get("data") if isinstance(_event.get("data"), dict) else {}
                _hook = _event.get("hook") or _data.get("hook")
                if _hook:
                    _discounted.add(str(_hook))

    observed = 0
    for field in _OBSERVED_BEHAVIOR_FIELDS:
        value = dynamic.get(field)
        if not isinstance(value, list):
            try:
                observed += len(value or [])
            except TypeError:
                pass
            continue
        for entry in value:
            if isinstance(entry, str) and entry in _discounted:
                continue
            if field == "files_accessed" and isinstance(entry, str):
                entry_lower = entry.lower()
                if any(pat in entry_lower for pat in _INTERNAL_RUNTIME_FILE_PATTERNS):
                    continue
            observed += 1

    # frida_events is a dict of per-category buckets. Sample behaviour is every
    # bucket except the sample's evasion and the harness's own actions.
    #
    # harness_action has to be skipped explicitly: it is a new bucket, and
    # without this the sandbox's Build-field spoofing would count as observed
    # sample behaviour - enough on its own to make an empty run read as
    # conclusive, which is the same misattribution this split exists to end,
    # only pointing the other way.
    buckets = dynamic.get("frida_events")
    if isinstance(buckets, dict):
        for name, events in buckets.items():
            upper = str(name).upper()
            if (
                upper in _EVASION_EVIDENCE_CATEGORIES
                or upper in _HARNESS_EVIDENCE_CATEGORIES
                or upper in _BASELINE_EVIDENCE_CATEGORIES
            ):
                continue
            try:
                observed += len(events or [])
            except TypeError:
                continue
    return observed


def _count_behavioural_evidence_records(dynamic: Dict) -> int:
    """
    Flushed evidence records that describe the SAMPLE, not the harness.

    `evidence_record_count` is a bare total that includes ScreenshotManager
    bookkeeping - on an evasion-only run it read 4 (1 real finding + 3 screenshot
    records) and single-handedly marked the run conclusive. Only the itemised
    `evidence` list can be filtered, so when it is absent this returns 0 rather
    than falling back to the unfiltered total.
    """
    records = dynamic.get("evidence")
    if not isinstance(records, list):
        return 0

    behavioural = 0
    for record in records:
        if not isinstance(record, dict):
            continue
        category = str(record.get("category") or "").upper()
        if category in _HARNESS_EVIDENCE_CATEGORIES:
            continue
        if category in _EVASION_EVIDENCE_CATEGORIES:
            continue
        if category in _BASELINE_EVIDENCE_CATEGORIES:
            continue
        behavioural += 1
    return behavioural


def _ui_never_rendered(dynamic: Dict) -> bool:
    """
    True when the process started but never presented an Activity or window.

    A sample that never rendered UI never reached the code paths the behavioural
    hooks cover, so a zero from that run describes the launch, not the sample.
    """
    timeline = dynamic.get("launch_timeline")
    if not isinstance(timeline, dict):
        return False
    if "first_activity" not in timeline and "first_window" not in timeline:
        return False
    return timeline.get("first_activity") is None and timeline.get("first_window") is None


def _dynamic_behavior_is_conclusive(dynamic: Dict) -> bool:
    """Whether observable sample behaviour exceeds the conclusive threshold."""
    observed = _count_observed_sample_behavior(dynamic)
    behavioural_records = _count_behavioural_evidence_records(dynamic)
    try:
        bfci_val = float(dynamic.get("bfci") or 0.0)
    except (TypeError, ValueError):
        bfci_val = 0.0

    if bfci_val >= _BFCI_SUBSTANTIVE:
        return True

    if observed < _MIN_DYNAMIC_EVENTS and behavioural_records < _MIN_DYNAMIC_EVENTS:
        return False

    # Behaviour was seen; a run that never rendered UI is still trustworthy only
    # if that behaviour is what produced the signal, which the checks above have
    # now established.
    return True


def reconcile_frs_breakdown(
    frs_breakdown: Optional[Dict],
    dynamic_result: Optional[Dict],
) -> Optional[Dict]:
    """
    Refresh dynamic-axis provenance when serving a stored case.

    Older payloads may omit `dynamic_conclusive` or mark the axis excluded even
    when `dynamic_result` contains conclusive behavioural evidence.
    """
    if not frs_breakdown or not isinstance(frs_breakdown, dict):
        return frs_breakdown
    if not dynamic_result or not isinstance(dynamic_result, dict):
        return frs_breakdown

    dynamic_available = bool(
        dynamic_result.get("available", False)
        or dynamic_result.get("runtime_attempted", False)
    )
    dynamic_conclusive = dynamic_available and _dynamic_run_was_conclusive(dynamic_result)
    correlation_available = "correlation" not in (frs_breakdown.get("axes_excluded") or [])

    axes = [
        ("stei", 0.25, True),
        ("dynamic", 0.35, dynamic_conclusive),
        ("correlation", 0.20, correlation_available),
        ("banking_impact", 0.20, True),
    ]
    live = [(name, weight) for name, weight, ok in axes if ok]
    total_weight = sum(weight for _, weight in live)
    axes_used = (
        {name: round(weight / total_weight, 3) for name, weight in live}
        if total_weight
        else {}
    )
    axes_excluded = [name for name, _, ok in axes if not ok]

    reconciled = dict(frs_breakdown)
    reconciled.update(
        {
            "dynamic_ran": dynamic_available,
            "dynamic_available": dynamic_available,
            "dynamic_conclusive": dynamic_conclusive,
            "dynamic_exclusion_reason": dynamic_exclusion_reason(dynamic_result),
            "axes_used": axes_used,
            "axes_excluded": axes_excluded,
        }
    )
    return reconciled


_INCONCLUSIVE_STATUSES = frozenset({
    "NO_BEHAVIOR_OBSERVED",
    "NO_UI_RENDERED",
    # Hooks installed, the process ran, and the agent arrived after the app had
    # already acted. The sandbox observed nothing about the sample, so scoring
    # the fraud axis from it would award a clean zero at 0.35 weight for a run
    # that measured the harness.
    "INSTRUMENTED_TOO_LATE",
    "INSTRUMENTATION_FAILED",
    "FRIDA_ATTACH_FAILED",
    "EMULATOR_UNAVAILABLE",
    "INSTALL_FAILED",
    "TIMEOUT",
    # The 30-minute wall clock arrived. Listed here so a run that hit it with
    # NOTHING observed is excluded rather than scored as a clean zero.
    #
    # A run that hit it WITH evidence is unaffected: dynamic_exclusion_reason
    # consults _dynamic_behavior_is_conclusive BEFORE it looks at the status, so
    # observed behaviour outranks the label - which is the whole §P16 rule that
    # a timeout with meaningful evidence is scored on that evidence.
    "TIME_BUDGET_EXHAUSTED",
    "FAILED",
    "PARTIAL",
    "CRASHED",
    "INCOMPLETE",
    "CRASHED_BEFORE_EXPLORATION",
    "BACKGROUND_SERVICE_RUNNING",
    "PID_NOT_FOUND",
})

_INCOMPLETE_DYNAMIC_STATUSES = frozenset({
    "PARTIAL",
    "CRASHED",
    "INCOMPLETE",
    "FAILED",
    "NO_UI_RENDERED",
    "INSTRUMENTATION_FAILED",
    "BACKGROUND_SERVICE_RUNNING",
    "CRASHED_BEFORE_EXPLORATION",
    "PID_NOT_FOUND",
    "FRIDA_ATTACH_FAILED",
    "TIMEOUT",
    "TIME_BUDGET_EXHAUSTED",
})


#: Dynamic-axis score awarded to a run whose only sample-attributable
#: observation is substantive evasion.
#:
#: Deliberately mid-band. It has to be high enough that including the axis
#: raises the verdict rather than diluting it - the whole reason evasion used to
#: be excluded was that a 0.0 at 0.35 weight read as "clean" - and low enough
#: that it never outranks a run which actually observed fraud behaviour, where
#: BFCI carries the score on its own.
_EVASION_RESISTANCE_SCORE: float = 45.0

#: Severities that make evasion a fight rather than a fingerprinting check.
_SUBSTANTIVE_EVASION_SEVERITIES = frozenset({"HIGH", "CRITICAL"})

#: Hooks that are themselves an attempt to defeat the analysis, whatever
#: severity the agent stamped on them. Self-termination is the clearest case:
#: an app ending its own process on detecting instrumentation is not probing
#: the environment, it is refusing to be watched.
_ACTIVE_EVASION_HOOKS = (
    "killProcess",
    "System.exit",
    "Runtime.exit",
    "Runtime.halt",
)


def _evasive_explains_the_silence(events: Any) -> bool:
    """
    Whether this evasion accounts for a run that produced no UI and no fraud.

    Narrower than _evasion_is_substantive on purpose. That function decides
    whether evasion is worth scoring at all; this one decides whether it
    outranks NO_UI_RENDERED, which is a stronger claim - it says the sample
    ENDED itself rather than merely probed its surroundings.

    Only self-termination qualifies. An app that read Build.MODEL and then
    showed no screen has not explained the missing screen; an app that called
    System.exit has.
    """
    for event in events or []:
        if not isinstance(event, dict):
            continue
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        hook = str(event.get("hook") or event.get("method") or data.get("hook") or "")
        if any(marker in hook for marker in _ACTIVE_EVASION_HOOKS):
            return True
    return False


def _evasion_is_substantive(events: Any) -> bool:
    """
    Whether this evasion is the sample fighting the analysis, not just looking.

    A Build.MODEL read is a fingerprinting check and must not be worth points.
    Killing your own process when hooks appear is a different act, and it is one
    we directly observed.
    """
    for event in events or []:
        if not isinstance(event, dict):
            continue
        if str(event.get("severity", "")).upper() in _SUBSTANTIVE_EVASION_SEVERITIES:
            return True
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        hook = str(event.get("hook") or event.get("method") or data.get("hook") or "")
        if any(marker in hook for marker in _ACTIVE_EVASION_HOOKS):
            return True
    return False


def dynamic_exclusion_reason(dynamic: Optional[Dict]) -> Optional[str]:
    """
    Why the dynamic axis cannot be scored, or None when it can.

    Consumers (report copy, the frontend runtime-behaviour card) need to tell an
    analyst *why* the axis reads zero. "No behaviour observed" and "the sample
    blocked us" are opposite claims and must not render identically.
    """
    if not dynamic or not dynamic.get("available", False):
        if dynamic and dynamic.get("runtime_attempted"):
            status = str(dynamic.get("dynamic_status") or "").upper()
            if status in _INCONCLUSIVE_STATUSES or status in (
                "EMULATOR_UNAVAILABLE", "INSTALL_FAILED", "FRIDA_ATTACH_FAILED",
            ):
                return status or "FAILED"
            return "DYNAMIC_UNAVAILABLE"
        return "DYNAMIC_UNAVAILABLE"

    status = str(dynamic.get("dynamic_status") or "").upper()
    outcome = str(dynamic.get("outcome") or "").upper()

    if _dynamic_behavior_is_conclusive(dynamic):
        if status == "NO_BEHAVIOR_OBSERVED":
            return "NO_BEHAVIOR_OBSERVED"

        # Observed SOMETHING, but nothing the fraud axis is made of.
        #
        # BFCI is computed only from the categories in BFCI_WEIGHTS. When none
        # of them fired, a BFCI of 0.0 is not a measurement of "no fraud" - it
        # is the absence of a measurement, and scoring it at the axis's 0.35
        # weight reads as "we looked and it was clean".
        #
        # Measured on Anubis: the axis excluded gives FRS 34.44 Suspicious; the
        # same run scored at 0.0 gives 19.38, inside the Safe band. Fifteen
        # points were lost for successfully analysing the sample, so a dropper
        # scored better by behaving during the window than by defeating the
        # sandbox. risk_engine's own note names this: "observing nothing scored
        # worse than failing to observe".
        #
        # This is the treatment the other inconclusive reasons already get. It
        # does not invent a score; it declines to award one from no data.
        return None

    # ── Why there was no UI matters more than that there was none ────────────
    #
    # This check used to come first, so a sample that killed itself the moment
    # it saw instrumentation was filed as "the app never rendered a screen" -
    # the reason for the silence discarded in favour of a description of it.
    #
    # Measured on Teabot: 80 hooks installed, Application.onCreate fired, then
    # Process.killProcess and System.exit. It did not fail to draw a window; it
    # refused to run. NO_UI_RENDERED excluded the axis and said nothing,
    # whereas the evasion is both an explanation and something we watched
    # happen.
    #
    # So substantive, sample-attributable evasion is consulted first: when we
    # know WHY nothing rendered, that answer wins. A run with no UI and no
    # evasion still falls through to NO_UI_RENDERED below, unchanged.
    _evasion = sample_attributable_evasion(dynamic.get("anti_analysis_events"))
    if _evasion and _evasive_explains_the_silence(_evasion):
        return None

    if _ui_never_rendered(dynamic):
        return "NO_UI_RENDERED"

    # Only the sample's own evasion counts. Reading this bucket raw meant the
    # harness's Build-field spoofing - one event, present on every emulator run
    # regardless of the sample - was enough to return EVASION_ONLY and exclude
    # the dynamic axis. Five banking trojans scored Safe that way.
    evasion_events = sample_attributable_evasion(dynamic.get("anti_analysis_events"))
    if evasion_events:
        # ── Resistance IS an observation about the sample ────────────────────
        #
        # Excluding here was protective, not principled: with BFCI at 0.0 the
        # axis would have scored a clean zero at 0.35 weight, so "we could not
        # observe it" would have read as "we observed nothing wrong". Excluding
        # avoided that, at the cost of the report saying nothing at all.
        #
        # But an app that detects instrumentation and kills itself has not
        # hidden from us - we watched it do that. Measured on a live sample:
        #   [CRITICAL] Process.killProcess - app attempted to self-terminate
        #   [CRITICAL] System.exit(10)     - app attempted to self-terminate
        # both blocked by the harness, both attributable to the sample rather
        # than to us (sample_attributable_evasion already strips the harness's
        # own Build-field spoof, which is why that filter exists).
        #
        # So the axis is scored on the resistance instead of excluded - see
        # _EVASION_RESISTANCE_SCORE. That raises the verdict rather than
        # diluting it, which is the honest direction: self-termination on
        # detection is behaviour no ordinary app exhibits.
        #
        # Low-severity evasion alone still excludes. A single Build.MODEL read
        # is a fingerprinting check, not a fight, and must not be worth points.
        if _evasion_is_substantive(evasion_events):
            return None
        return "EVASION_ONLY"

    if status in _INCONCLUSIVE_STATUSES or outcome == "FAILED":
        return status or "FAILED"

    return "NO_BEHAVIOR_OBSERVED"


def _dynamic_coverage_block(dynamic: Optional[Dict]) -> Dict[str, Any]:
    """
    Coverage and validity metadata for the FRS breakdown.

    Read from the dynamic result's own `dynamic_coverage` block when it has one
    (every run produced by the current sandbox does), and reconstructed
    conservatively when serving a STORED case from before the block existed -
    an old payload must not suddenly report zero coverage, which would read as
    a regression in the sample rather than in the record.

    Nothing here is scored. The score comes from BFCI, computed from observed
    events; this is what the score TRAVELS WITH, so a partial run can never be
    reported as though it were a complete one.
    """
    if not isinstance(dynamic, dict):
        return {
            "dynamic_status": "SKIPPED",
            "dynamic_valid": False,
            "dynamic_complete": False,
            "dynamic_coverage_ratio": 0.0,
            "goals_total": 0,
            "goals_successful": 0,
            "coverage_known": False,
            "limitations": [],
        }

    block = dynamic.get("dynamic_coverage")
    if isinstance(block, dict) and block:
        return {
            "dynamic_status": block.get("dynamic_status", ""),
            "dynamic_valid": bool(block.get("dynamic_valid")),
            "dynamic_complete": bool(block.get("dynamic_complete")),
            "dynamic_coverage_ratio": float(block.get("coverage_ratio") or 0.0),
            "goals_total": int(block.get("goals_total") or 0),
            "goals_successful": int(block.get("goals_successful") or 0),
            "goals_partial": int(block.get("goals_partial") or 0),
            "goals_failed": int(block.get("goals_failed") or 0),
            "goals_skipped": int(block.get("goals_skipped") or 0),
            "goals_not_reached": int(block.get("goals_not_reached") or 0),
            "coverage_known": True,
            "timeout_reason": block.get("timeout_reason"),
            "limitations": list(block.get("limitations") or []),
            "coverage_narrative": block.get("narrative", ""),
        }

    # Legacy payload. `coverage_known` False is the load-bearing field: it tells
    # the report to say "coverage was not recorded for this run" rather than to
    # print a zero that would read as "nothing was covered".
    return {
        "dynamic_status": str(dynamic.get("dynamic_status") or ""),
        "dynamic_valid": bool(_dynamic_run_was_conclusive(dynamic)),
        "dynamic_complete": False,
        "dynamic_coverage_ratio": 0.0,
        "goals_total": 0,
        "goals_successful": 0,
        "coverage_known": False,
        "limitations": [],
    }


def _dynamic_run_was_conclusive(dynamic: Optional[Dict]) -> bool:
    """
    Did the sandbox actually observe enough to reason about?

    A run is conclusive when the sample exhibited enough observable behaviour
    (hook events, behavioural evidence records, or BFCI >= 20). Harness faults
    (INSTRUMENTATION_FAILED) do not override real sample behaviour - native
    anti-analysis hooks can still fire when the Java bridge fails.

    Three things deliberately do NOT make a run conclusive, because each would
    let a launch failure masquerade as a clean bill of health at the dynamic
    axis's full 0.35 weight:
      * screenshot/harness evidence records (see _count_behavioural_evidence_records)
      * anti-analysis events alone - evasion is resistance, not behaviour
      * a run where the process started but never rendered UI
    """
    return dynamic_exclusion_reason(dynamic) is None




def _calculate_dynamic_score(dynamic: Optional[Dict]) -> Tuple[float, List[str]]:
    """
    Dynamic behavioral score dispatcher.

    - If engine = 'frida': uses the exact BFCI formula
      BFCI = (wa × A) + (ws × S) + (wo × O) + (wb × B) + (wn × N) + (wp × P)
    - If engine = 'mobsf': uses hook-string matching with flat bonuses
      (MobSF does not expose per-component weights)
    - If not available: returns 0 (static-only mode, STEI weight is redistributed)
    """
    if not dynamic or not dynamic.get("available"):
        return 0.0, ["Dynamic analysis not available - using static-only mode"]

    engine = dynamic.get("engine", "mobsf")

    # ── Frida path: proper BFCI formula ───────────────────────────────────────
    if engine == "frida":
        score, evidence = _calculate_bfci_from_frida(dynamic)
        # A run whose only sample-attributable observation is substantive
        # evasion scores on the resistance instead of on BFCI, which is
        # legitimately 0.0 - none of the fraud buckets fired, and that stays
        # true in the reported components.
        #
        # Without this the axis is included (see dynamic_exclusion_reason) at
        # 0.0, and a sample that fought the sandbox would score exactly like
        # one that sat still - the outcome the exclusion existed to prevent.
        if score <= 0.0:
            evasion_events = sample_attributable_evasion(
                dynamic.get("anti_analysis_events")
            )
            if evasion_events and _evasion_is_substantive(evasion_events):
                return _EVASION_RESISTANCE_SCORE, evidence + [
                    f"Sample actively resisted analysis: "
                    f"{len(evasion_events)} anti-analysis action(s) attributable "
                    f"to the app, including attempts to terminate its own "
                    f"process when instrumentation was detected. Scored "
                    f"{_EVASION_RESISTANCE_SCORE:.0f}/100 on the dynamic axis - "
                    f"BFCI remains 0.0 because no fraud capability fired, which "
                    f"is what the sample prevented."
                ]
        return score, evidence

    # ── MobSF path: flat-bonus approximation ──────────────────────────────────
    score = 0.0
    evidence: List[str] = []

    api_calls_str = str(dynamic.get("api_calls", []))

    # Accessibility (wa = 0.35 → maps to +35 at full confidence)
    if "accessibilityservice" in api_calls_str.lower():
        score += 35.0
        evidence.append("Runtime Accessibility abuse confirmed - MobSF (BFCI component A, wa=0.35, +35)")

    # SMS interception (ws = 0.25 → +25)
    if "readtext" in api_calls_str.lower() or "sms" in api_calls_str.lower():
        score += 25.0
        evidence.append("Runtime SMS/OTP interception confirmed - MobSF (BFCI component S, ws=0.25, +25)")

    # Overlay (wo = 0.20 → +20)
    if "windowmanager" in api_calls_str.lower() or "overlay" in api_calls_str.lower():
        score += 20.0
        evidence.append("Runtime overlay window confirmed - MobSF (BFCI component O, wo=0.20, +20)")

    # Network C2 (wn = 0.05 → up to +5)
    network_logs = dynamic.get("network_logs", [])
    if network_logs:
        net_contribution = min(len(network_logs) * 0.5, 5.0)
        score += net_contribution
        evidence.append(
            f"{len(network_logs)} C2 network connections observed "
            f"(BFCI component N, wn=0.05, +{net_contribution:.1f})"
        )

    # Persistence (wp = 0.05 → +5)
    files_accessed = dynamic.get("files_accessed", [])
    suspicious_paths = [f for f in files_accessed if any(p in f for p in ["/data/data", "/sdcard/", "/system/"])]
    if suspicious_paths:
        score += min(len(suspicious_paths) * 1.0, 5.0)
        evidence.append(
            f"Suspicious file access: {suspicious_paths[:2]} "
            f"(BFCI component P, wp=0.05, +{min(len(suspicious_paths), 5):.0f})"
        )

    # Screenshots - not in BFCI formula, added as bonus
    screenshots = dynamic.get("screenshots", [])
    if screenshots:
        score += 10.0
        evidence.append(f"Screen capture observed - {len(screenshots)} screenshot(s) (+10 bonus)")

    return min(round(score, 2), 100.0), evidence


# ─── Correlation Score ────────────────────────────────────────────────────────

def _calculate_correlation_score(correlation: Optional[Dict]) -> Tuple[float, List[str]]:
    """Convert threat correlation result to 0–100 score."""
    if not correlation or not correlation.get("available"):
        return 0.0, ["No threat intelligence correlation available (no API keys configured)"]

    score = correlation.get("threat_score", 0.0)
    evidence: List[str] = correlation.get("threat_score_sources", [])

    family = correlation.get("known_family")
    if family:
        evidence.append(f"Known malware family: {family}")

    return min(round(score, 2), 100.0), evidence


# ─── Banking Impact Score (BFCI) ──────────────────────────────────────────────

def _calculate_banking_impact(
    flags: Dict[str, Any],
    family: str,
    correlation: Optional[Dict] = None,
) -> Tuple[float, List[str]]:
    """
    BFCI (Banking Financial Crime Impact):
      = banking_targeting + family_weight + regulatory_risk

    Normalized to 0–100.
    """
    evidence: List[str] = []
    score = 0.0

    # Banking targeting
    bank_pkgs = flags.get("indian_bank_packages_found", [])
    if flags.get("targets_indian_banks"):
        targeting_score = min(10.0 + len(bank_pkgs) * 5, 40.0)
        score += targeting_score
        evidence.append(f"{len(bank_pkgs)} Indian banking package(s) targeted (+{targeting_score:.0f})")

    # Malware family weight
    family_weight = FAMILY_BANKING_WEIGHT.get(family, 0.5)
    if family != "Unknown":
        family_score = family_weight * 40.0
        score += family_score
        evidence.append(f"Malware family {family} (severity weight {family_weight}) (+{family_score:.0f})")
    else:
        score += 20.0  # Unknown but flagged
        evidence.append("Unknown family - moderate banking impact assumed (+20)")

    # Regulatory risk - banks are mandated to act on these
    if flags.get("has_sms_read_write") and flags.get("targets_indian_banks"):
        score += 20.0
        evidence.append("RBI MDS-2021 OTP interception violation - regulatory risk (+20)")

    # Campaign attribution from correlation
    if correlation and correlation.get("campaign"):
        score += 15.0
        evidence.append(f"Active campaign detected: {correlation['campaign']} (+15)")

    return min(round(score, 2), 100.0), evidence


# ─── Full FRS Calculation ─────────────────────────────────────────────────────

def calculate_risk_score(
    flags: Any,  # Accept StaticAnalysisFlags or Dict
    ai_confidence: float = 1.0,
    dynamic_result: Optional[Dict] = None,
    correlation_result: Optional[Dict] = None,
    family: str = "Unknown",
    all_permissions: Optional[List[str]] = None,
    vide_result: Optional[Dict] = None,
) -> Dict[str, Any]:
    """
    Full Fraud Risk Score (FRS) calculation.

    FRS = 0.25 × STEI + 0.35 × Dynamic + 0.20 × Correlation + 0.20 × BankingImpact

    STEI uses the PDF's exact 5-axis formula:
      STEI = 0.60×CT + 0.20×BT + 0.10×PR + 0.05×OB + 0.05×IR

    Args:
        flags: StaticAnalysisFlags or dict with flag data
        ai_confidence: multiplier from deterministic classification (1.0 or 1.2)
        dynamic_result: optional MobSF/Frida dynamic analysis result
        correlation_result: optional threat correlator result
        family: detected malware family name
        all_permissions: full list of manifest permissions (for PR axis)

    Returns:
        Full risk result dict with component scores, axes breakdown, and evidence
    """
    # Normalize flags to dict
    if hasattr(flags, "__dict__"):
        flags_dict = {
            "has_accessibility_abuse": flags.has_accessibility_abuse,
            "has_sms_read_write": flags.has_sms_read_write,
            "has_system_alert_window": flags.has_system_alert_window,
            "dangerous_apis_found": flags.dangerous_apis_found,
            "hardcoded_urls_ips": flags.hardcoded_urls_ips,
            "targets_indian_banks": flags.targets_indian_banks,
            "indian_bank_packages_found": getattr(flags, "indian_bank_packages_found", []),
            "obfuscation_score": getattr(flags, "obfuscation_score", 0.0),
            "has_reflection": getattr(flags, "has_reflection", False),
            "has_concealed_payload": getattr(flags, "has_concealed_payload", False),
            "concealment_evidence": getattr(flags, "concealment_evidence", []),
            "limited_static_visibility": getattr(flags, "limited_static_visibility", False),
        }
    else:
        flags_dict = flags

    if vide_result:
        flags_dict = dict(flags_dict)
        flags_dict["visual_impersonation_detected"] = bool(
            vide_result.get("visual_impersonation_detected")
        )
        flags_dict["visual_impersonation_institution"] = vide_result.get(
            "visual_impersonation_institution", ""
        )
        flags_dict["visual_impersonation_confidence"] = vide_result.get(
            "visual_impersonation_confidence", 0.0
        )
        flags_dict["signer_impersonation_detected"] = bool(
            (vide_result.get("signer_impersonation") or {}).get("detected")
        )

    # ── Component Scores ──────────────────────────────────────────────────────
    stei, stei_axes, stei_evidence, stei_by_axis = _calculate_stei(flags_dict, all_permissions)
    dynamic_score, dynamic_evidence = _calculate_dynamic_score(dynamic_result)
    correlation_score, corr_evidence = _calculate_correlation_score(correlation_result)
    banking_score, banking_evidence = _calculate_banking_impact(flags_dict, family, correlation_result)

    # ── Threat Scenario Table ─────────────────────────────────────────────────
    scenario_table = build_threat_scenario_table(flags_dict)

    # ── FRS Formula ───────────────────────────────────────────────────────────
    dynamic_available = dynamic_result is not None and (
        dynamic_result.get("available", False)
        or dynamic_result.get("runtime_attempted", False)
    )

    # An axis with no data must be EXCLUDED, not scored as 0.
    #
    # Previously an unconfigured threat-intel provider contributed
    # `0.20 * 0.0`, so 20-25% of every score was pinned at zero in any
    # deployment without VirusTotal/OTX/AbuseIPDB keys. That is absence of
    # evidence being treated as evidence of innocence, and it is why real
    # banking trojans landed in the "Safe" band: measured on the labelled
    # corpus, Teabot scored 30.8 with correlation forced to 0, versus 41.1
    # when the axis is properly excluded and the remaining weights renormalised.
    #
    # The author already knew this pattern - the old code redistributed the
    # dynamic weight - it just was not applied to correlation.
    correlation_available = bool(correlation_result and correlation_result.get("available"))

    # A sandbox run that observed nothing is INCONCLUSIVE, not clean.
    #
    # Evasive malware is built to stay dormant under analysis - banking trojans
    # routinely fingerprint ADB, Frida and emulator properties and suppress
    # behaviour. Scoring "no events captured" as a near-zero dynamic value meant
    # the axis with the LARGEST weight actively diluted strong static evidence,
    # so the better a sample's evasion, the safer this engine rated it.
    #
    # Measured on Cerberus: static-only 38.74 "Suspicious"; after a 30 s run that
    # captured 0 API calls and 0 network events, the dynamic axis took 0.437 of
    # the weight at a value of 5.0 and pulled the verdict down to 23.98 "Safe".
    #
    # This is NOT "dynamic may only ever raise the score" - a run with real
    # coverage that observes benign behaviour is legitimate evidence and still
    # lowers it. The distinction is whether the sandbox actually observed
    # anything to reason about.
    dynamic_conclusive = dynamic_available and _dynamic_run_was_conclusive(dynamic_result)

    # ── Coverage is not validity, and neither is completeness ────────────────
    #
    # Four separate questions were previously collapsed into one boolean, which
    # is why a partial run could not be distinguished from a failed one in the
    # report:
    #
    #   dynamic_available   Was the dynamic infrastructure there at all?
    #   dynamic_valid       Did we obtain trustworthy dynamic evidence?
    #   dynamic_complete    Were all planned investigation goals completed?
    #   dynamic_coverage    How much of the plan was exercised?
    #
    # These are REPORTED, not scored. `dynamic_conclusive` above still decides
    # whether the axis is included, and it is still derived from observed
    # evidence rather than from goal completion - so a run with 60% coverage
    # whose observed events clear the threshold is scored exactly as it always
    # was, and one with 100% coverage and no events is still excluded. What
    # changes is that the analyst can now see which of the two they are looking
    # at instead of both reading as "inconclusive".
    dynamic_coverage_block = _dynamic_coverage_block(dynamic_result)

    axes = [("stei", 0.25, stei, True)]
    axes.append(("dynamic", 0.35, dynamic_score, dynamic_conclusive))
    axes.append(("correlation", 0.20, correlation_score, correlation_available))
    axes.append(("banking_impact", 0.20, banking_score, True))

    live = [(n, w, v) for (n, w, v, ok) in axes if ok]
    total_weight = sum(w for _, w, _ in live)
    frs = sum(w * v for _, w, v in live) / total_weight if total_weight else 0.0

    axes_used = {n: round(w / total_weight, 3) for n, w, _ in live} if total_weight else {}
    axes_excluded = [n for (n, _, _, ok) in axes if not ok]

    # Apply AI confidence multiplier (1.0 or 1.2)
    ai_multiplier = max(0.5, min(ai_confidence, 1.5))
    final_score = min(frs * ai_multiplier, 100.0)

    # Compute static baseline score (excluding dynamic axis)
    static_axes = [
        ("stei", 0.25, stei),
        ("correlation", 0.20, correlation_score if correlation_available else 0.0),
        ("banking_impact", 0.20, banking_score),
    ]
    static_live = [(n, w, v) for (n, w, v) in static_axes if (n != "correlation" or correlation_available)]
    static_total_weight = sum(w for _, w, _ in static_live)
    static_frs = (sum(w * v for _, w, v in static_live) / static_total_weight) if static_total_weight else 0.0
    static_score = min(static_frs * ai_multiplier, 100.0)

    try:
        _reported_bfci = float((dynamic_result or {}).get("bfci") or 0.0)
    except (TypeError, ValueError):
        _reported_bfci = 0.0

    # ── Static Floor for Incomplete Dynamic Analysis ───────────────────────────
    # A failed or incomplete dynamic run must NEVER reduce the overall risk score below
    # the static score. When the sandbox cannot run or crashes or renders no UI,
    # dynamic absence cannot be credited as safety.
    static_floor_applied = False
    static_floor_score = None
    static_floor_reason = None

    if dynamic_available:
        dyn_status = str((dynamic_result or {}).get("dynamic_status") or "").upper()
        has_cov = dynamic_coverage_block.get("coverage_known", False)
        dyn_complete = bool(dynamic_coverage_block.get("dynamic_complete"))
        dyn_coverage_ratio = float(dynamic_coverage_block.get("dynamic_coverage_ratio") or 0.0)

        is_incomplete_dynamic = (
            dyn_status in _INCOMPLETE_DYNAMIC_STATUSES
            or (has_cov and (not dyn_complete or dyn_coverage_ratio < 0.5))
        )

        if is_incomplete_dynamic and final_score < static_score:
            static_floor_applied = True
            static_floor_score = round(static_score, 2)
            cov_str = f"{dyn_coverage_ratio:.1%}" if has_cov else "N/A"
            static_floor_reason = (
                f"Dynamic run was incomplete (status={dyn_status or 'UNKNOWN'}, "
                f"coverage={cov_str}, bfci={_reported_bfci:.1f}) and reduced "
                f"risk score from static score {static_score:.2f} down to {final_score:.2f}. "
                f"Static floor enforced: an incomplete dynamic run must NOT lower the overall risk score."
            )
            logger.info("[RiskEngine] %s", static_floor_reason)
            final_score = static_score

    # CH06 / VIDE deterministic escalations (P1: cluster required for visual-only)
    vide_evidence: List[str] = []
    ch27_triad = False
    if vide_result:
        for line in (vide_result.get("vide_compare") or {}).get("evidence_lines") or []:
            vide_evidence.append(line)
        for line in (vide_result.get("signer_impersonation") or {}).get("evidence_lines") or []:
            vide_evidence.append(line)

        # ── CH27: the On-Device Fraud triad ───────────────────────────────
        # A high-confidence visual clone, signed by someone other than the
        # bank, that also asks for the accessibility service is the complete
        # ATS kill chain: it looks like the bank, it is not the bank, and it
        # can drive the screen. Each signal alone is defensible - a skinned
        # theme, a re-signed build, a legitimate screen reader - so CRITICAL
        # is reserved for all three together.
        ch27_confidence = float(
            vide_result.get("visual_impersonation_confidence") or 0.0
        )
        ch27_triad = (
            ch27_confidence > 0.85
            and bool(vide_result.get("signer_impersonation", {}).get("detected"))
            and bool(flags_dict.get("has_accessibility_abuse"))
        )
        if ch27_triad:
            final_score = max(final_score, 95.0)
            vide_evidence.append(
                "CH27: visual impersonation "
                f"({ch27_confidence:.2f} confidence) + signer mismatch + "
                "BIND_ACCESSIBILITY_SERVICE - complete on-device fraud chain"
            )

        if vide_result.get("signer_impersonation", {}).get("detected"):
            final_score = max(final_score, 92.0)
        elif vide_result.get("critical_visual_cluster"):
            final_score = max(final_score, 88.0)
        elif vide_result.get("visual_impersonation_detected"):
            final_score = max(final_score, min(55.0 + float(
                vide_result.get("visual_impersonation_confidence") or 0.0
            ) * 35.0, 75.0))

    final_rounded = round(final_score, 2)

    # ── Risk Band ─────────────────────────────────────────────────────────────
    if final_score <= 30:
        band = "Safe"
    elif final_score <= 60:
        band = "Suspicious"
    elif final_score <= 89:
        band = "High Risk"
    else:
        band = "Critical"

    if ch27_triad:
        band = "Critical"
    elif vide_result and vide_result.get("signer_impersonation", {}).get("detected"):
        band = "Critical"
    elif vide_result and vide_result.get("critical_visual_cluster"):
        band = "Critical"

    base_score = round(frs, 2)

    # ── Visibility floor ──────────────────────────────────────────────────────
    # "We could not see the code" is not the same claim as "the code is safe".
    #
    # A dropper ships a stub manifest and unpacks its real payload at runtime, so
    # every capability-based axis reads near zero and the arithmetic lands in
    # "Safe". On the labelled corpus Anubis (4 permissions) and Hook (1
    # permission, 0 services, a nested assets/base.apk) both scored below a file
    # manager for exactly this reason.
    #
    # This does NOT assert the sample is malicious - the score is left untouched.
    # It refuses to certify as safe something that was never actually analysed,
    # and says so in the evidence.
    #
    # What resolves the ambiguity is dynamic analysis that ACTUALLY OBSERVED the
    # payload, not merely a run that completed. Gating on `dynamic_conclusive`
    # alone let a dropper walk: Anubis produced one incidental API call, enough
    # to mark the run conclusive, while BFCI stayed 0.0 because the second stage
    # never deployed inside the capture window. The floor switched off and a
    # banking trojan scored 8.72 "Safe". A dropper that withholds its payload is
    # exactly the case this floor exists for, so the test is whether the dynamic
    # axis scored anything - not whether the sandbox managed to run.
    # "Observed the payload" means the run produced a SUBSTANTIVE fraud-relevant
    # signal, not a trickle. Two real cases set this bar:
    #   * Anubis logged one incidental API call and zero weighted behaviour.
    #   * Octo scored BFCI 4.8 - its network component maxed at 96 but network
    #     carries a 0.05 weight - and that 4.8 was enough to lift the floor and
    #     certify a heavily obfuscated sample with a concealed payload, static
    #     accessibility and SMS flags, and 31 permissions as "Safe" at 29.49.
    # Both the computed axis score and the sandbox's reported BFCI are consulted,
    # because the axis recomputes from bfci_components and reads 0 when a payload
    # reports bfci without them.
    try:
        _reported_bfci = float((dynamic_result or {}).get("bfci") or 0.0)
    except (TypeError, ValueError):
        _reported_bfci = 0.0
    payload_was_observed = dynamic_conclusive and (
        dynamic_score >= _BFCI_SUBSTANTIVE or _reported_bfci >= _BFCI_SUBSTANTIVE
    )

    visibility_floored = False
    if band == "Safe" and flags_dict.get("has_concealed_payload") and not payload_was_observed:
        band = "Suspicious"
        visibility_floored = True
        if dynamic_conclusive:
            stei_evidence.append(
                "VERDICT FLOORED: payload is concealed and the sandbox observed "
                "no payload behaviour, so the code that actually runs was never "
                "seen. Not rated Safe - a dropper withholding its second stage "
                "produces exactly this result."
            )
        else:
            stei_evidence.append(
                "VERDICT FLOORED: payload is concealed and no dynamic analysis was "
                "available, so static analysis could not observe the code that will "
                "actually run. Not rated Safe - run dynamic analysis to resolve."
            )

    # ── Static evidence floor ─────────────────────────────────────────────────
    # An empty sandbox run must not overturn strong declared capability.
    #
    # Cerberus: STEI 53.73 from READ/SEND/RECEIVE_SMS across 17 permissions. One
    # run captured no telemetry, the dynamic axis was excluded, and it scored
    # 39.11 "Suspicious". The next run reached the app, observed no fraud
    # behaviour within the window, and that 0.0 at 0.35 weight pulled the same
    # binary to 25.42 "Safe" - observing nothing scored worse than failing to
    # observe. A 90 second window not triggering SMS interception is not evidence
    # that the SMS interception is absent; the permissions are still declared.
    #
    # Scoring is untouched. This only refuses the Safe certification, and only
    # when the sandbox produced no fraud-relevant signal at all.
    static_evidence_floored = False
    if (
        band == "Safe"
        and stei >= _STEI_STRONG
        and dynamic_score <= 0.0
        and _reported_bfci <= 0.0
    ):
        band = "Suspicious"
        static_evidence_floored = True
        stei_evidence.append(
            f"VERDICT FLOORED: static analysis found strong fraud capability "
            f"(STEI {stei:.1f}) and the sandbox observed no behaviour that "
            f"refutes it. Not rated Safe - an empty run is not an acquittal."
        )

    # ── Evasion floor ─────────────────────────────────────────────────────────
    # A sample that fingerprints the sandbox has told us something about itself,
    # but it scores nothing: anti_analysis carries no BFCI weight, so the only
    # observable act on an evasion-only run contributes exactly 0.0. Combined
    # with the dynamic axis being excluded, active evasion could leave a verdict
    # of "Safe" - the sample's counter-analysis working as designed.
    #
    # Like the visibility floor above, this does not invent a score. It refuses
    # to certify as safe a sample that resisted being observed, and says so.
    evasion_floored = False
    evasion_reason = dynamic_exclusion_reason(dynamic_result) if dynamic_available else None
    try:
        evasion_event_count = len((dynamic_result or {}).get("anti_analysis_events") or [])
    except TypeError:
        evasion_event_count = 0
    if (
        band == "Safe"
        and not dynamic_conclusive
        and evasion_event_count > 0
        and evasion_reason in {"EVASION_ONLY", "NO_UI_RENDERED", "INSTRUMENTATION_FAILED"}
    ):
        band = "Suspicious"
        evasion_floored = True
        dynamic_evidence.append(
            f"VERDICT FLOORED: the sample performed {evasion_event_count} "
            "anti-analysis check(s) and then produced no observable behaviour, so "
            "the sandbox run cannot certify it. Evasion is not evidence of safety."
        )

    # ── Execution Assertion Matrix / INCOMPLETE_EXERCISE ─────────────────────
    # "Nothing happened" is not a finding about the sample until we know the
    # sample was actually exercised.
    #
    # The floors above each answer "we could not see" for a specific reason
    # (concealed payload, active evasion, strong static capability). This one
    # answers a different question: were the sample's own trigger conditions
    # ever reached? Anatsa waits for a targeted bank app to come to the
    # foreground; SOVA waits on an accessibility grant; an SMS stealer waits for
    # a message to arrive. A sterile run meets none of them, and the resulting
    # silence describes the harness, not the malware.
    assertions = build_execution_assertions(
        dynamic_result,
        target_bank_packages=flags_dict.get("indian_bank_packages_found"),
        threat_events_observed=(
            _count_observed_sample_behavior(dynamic_result) if dynamic_available else 0
        ),
    )
    incomplete_exercise = assertions.incomplete_exercise
    verdict = VERDICT_INCOMPLETE_EXERCISE if incomplete_exercise else band
    incomplete_exercise_floored = False
    if incomplete_exercise:
        dynamic_evidence.extend(assertions.evidence_lines())
        if band == "Safe":
            # Same treatment as the other floors: the score is not invented,
            # the Safe certification is refused. `risk_band` keeps its existing
            # four-value vocabulary so every downstream consumer keeps working;
            # `verdict` carries the INCOMPLETE_EXERCISE label.
            band = "Suspicious"
            incomplete_exercise_floored = True
            dynamic_evidence.append(
                "VERDICT FLOORED: no fraud trigger condition was reached during "
                "the sandbox run, so the absence of malicious behaviour is "
                "unexplained rather than exonerating. Re-run with the suggested "
                "triggers before drawing a conclusion."
            )

    # ── Confidence ───────────────────────────────────────────────────────────
    sources_available = sum([
        1,                                              # Static always available
        1 if dynamic_conclusive else 0,
        1 if correlation_result and correlation_result.get("available") else 0,
    ])
    confidence = round(60 + (sources_available / 3) * 35 + (2 if family != "Unknown" else 0), 1)
    # Concealed payload with no dynamic run means the analysis largely missed the
    # code. Reporting the usual confidence there would overstate the result.
    if flags_dict.get("has_concealed_payload") and not dynamic_conclusive:
        confidence = min(confidence, 45.0)
    # An inconclusive sandbox run is not corroboration; do not let it inflate
    # confidence via sources_available.
    if dynamic_available and not dynamic_conclusive:
        confidence = min(confidence, 60.0)
    # An unexercised run produced no information about the sample, so whatever
    # confidence the other axes earned must not be reported as if the sandbox
    # corroborated them.
    if incomplete_exercise:
        confidence = round(confidence * INCOMPLETE_EXERCISE_CONFIDENCE_PENALTY, 1)
    confidence = min(confidence, 99.0)

    all_evidence = stei_evidence + dynamic_evidence + corr_evidence + banking_evidence + vide_evidence

    return {
        # Legacy fields (keep backward compat)
        "base_score": base_score,
        "ai_confidence_multiplier": round(ai_multiplier, 2),
        "final_risk_score": final_rounded,
        "risk_band": band,

        # Verdict is `risk_band` in the ordinary case and INCOMPLETE_EXERCISE
        # when the sandbox never exercised the sample. Kept as a separate field
        # so `risk_band` retains its four-value vocabulary for the report
        # renderers, the PDF and the frontend badge colours.
        "verdict": verdict,
        "execution_assertions": assertions.to_dict(),
        "incomplete_exercise": incomplete_exercise,

        # Full FRS breakdown with 5-axis STEI
        "frs_breakdown": {
            "stei": round(stei, 2),
            "dynamic": round(dynamic_score, 2),
            "correlation": round(correlation_score, 2),
            "banking_impact": round(banking_score, 2),
            "formula_used": "full_frs" if dynamic_available else "static_only_frs",
            # Which axes actually contributed, and at what renormalised weight.
            # An excluded axis is one with no data - it is not scored as benign.
            "axes_used": axes_used,
            "axes_excluded": axes_excluded,
            "concealed_payload": bool(flags_dict.get("has_concealed_payload")),
            "dynamic_ran": dynamic_available,
            "dynamic_conclusive": dynamic_conclusive,

            # ── Coverage and validity, reported alongside the score ──────────
            # `dynamic_conclusive` above decides whether the axis is SCORED and
            # is unchanged: it reads observed evidence, never goal completion.
            # These four say what kind of run produced that score, so a partial
            # run cannot silently read as a complete one:
            #
            #   COMPLETE                use the dynamic score normally
            #   PARTIAL                 score the observed evidence, and say so
            #   TIME_BUDGET_EXHAUSTED   score the observed evidence when there
            #                           is any; otherwise treat as no behaviour
            #   NO_BEHAVIOR_OBSERVED    do not pretend evidence exists; the
            #                           static/evasion floors stay in force
            #   INSTRUMENTATION_FAILED  exclude the axis and renormalise
            #   SKIPPED                 exclude the axis
            #
            # All six of those outcomes are already produced by the existing
            # exclusion logic. What is added here is the LABEL, so the report
            # and the UI stop rendering "partial with evidence" and "we never
            # got to look" identically.
            "dynamic_status": dynamic_coverage_block.get("dynamic_status", ""),
            "dynamic_valid": dynamic_coverage_block.get("dynamic_valid", False),
            "dynamic_complete": dynamic_coverage_block.get("dynamic_complete", False),
            "dynamic_coverage": dynamic_coverage_block,
            "verdict_floored_for_visibility": visibility_floored,
            "verdict_floored_for_evasion": evasion_floored,
            "verdict_floored_for_static_evidence": static_evidence_floored,
            "verdict_floored_for_incomplete_exercise": incomplete_exercise_floored,
            "static_floor_applied": static_floor_applied,
            "static_floor_score": static_floor_score,
            "static_floor_reason": static_floor_reason,
            # Why the dynamic axis could not be scored. The UI must distinguish
            # "nothing bad happened" from "we never got to look".
            "dynamic_exclusion_reason": evasion_reason,
            "dynamic_available": dynamic_available,
            # 5-axis STEI breakdown
            "stei_axes": {
                "ct": stei_axes.get("ct", 0.0),
                "bt": stei_axes.get("bt", 0.0),
                "pr": stei_axes.get("pr", 0.0),
                "ob": stei_axes.get("ob", 0.0),
                "ir": stei_axes.get("ir", 0.0),
            },
            # Which STEI axes carried no evidence because the payload is
            # concealed. Without this the reader sees CT 0.0 next to a STEI of
            # 46 and cannot reconstruct the arithmetic - the axis was dropped
            # and the rest renormalised, not scored as a zero. An unexplained
            # number is the same defect as a wrong one.
            "stei_axes_excluded": list(stei_axes.get("excluded") or []),
            # Renormalised per-axis STEI weights, so the score ledger shows the
            # arithmetic that was actually performed rather than a nominal one.
            "stei_weights_used": dict(stei_axes.get("weights_used") or {}),
        },

        # Threat scenario correlation table
        "threat_scenario_table": scenario_table,

        "confidence": confidence,
        "severity": band,
        "evidence": all_evidence[:12],  # Cap evidence list for payload size
        "risk_explanation": {
            "evidence_lines": all_evidence[:48],
            "component_evidence": {
                "stei": stei_evidence,
                "dynamic": dynamic_evidence,
                "correlation": corr_evidence,
                "banking": banking_evidence,
            },
            "stei_evidence_by_axis": stei_by_axis,
        },
        "recommended_action": _get_recommended_action(band, family, flags_dict),
        "vide_result": vide_result or {},
    }


def _get_recommended_action(band: str, family: str, flags: Dict) -> str:
    """Return primary SOC recommended action based on risk band."""
    sep = " - "
    if band == "Critical":
        if family != "Unknown":
            return (
                f"IMMEDIATE BLOCK{sep}{family} confirmed. Isolate all affected devices. "
                "Engage IR team. Issue customer advisory per RBI CPG-2022."
            )
        return (
            f"IMMEDIATE BLOCK{sep}Critical behavioral signature. Isolate devices, "
            "revoke banking sessions, escalate to CISO."
        )
    if band == "High Risk":
        return (
            f"BLOCK & INVESTIGATE{sep}Do not deploy. Submit to dynamic sandbox. "
            "Notify SOC lead. Consider customer advisory."
        )
    if band == "Suspicious":
        return (
            f"QUARANTINE{sep}Further analysis required. Do not approve for enterprise "
            "deployment. Monitor network traffic."
        )
    return (
        f"MONITOR{sep}Low risk. Approved for deployment under standard monitoring. "
        "Re-scan on next version update."
    )
