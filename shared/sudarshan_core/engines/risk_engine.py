# backend/app/engines/risk_engine.py
"""
Sudarshan Deterministic Risk Engine
======================================
Implements the full Fraud Risk Score (FRS) formula from the Sudarshan proposal:

  FRS = 0.25 × STEI + 0.35 × Dynamic + 0.20 × Correlation + 0.20 × BankingImpact

STEI — 5-axis formula (PDF spec):
  STEI = 0.60 × CT  +  0.20 × BT  +  0.10 × PR  +  0.05 × OB  +  0.05 × IR

  Where:
    CT  — Credential Theft axis       (accessibility + SMS + overlay signals)
    BT  — Banking Targeting axis      (Indian bank package matches)
    PR  — Permission Risk axis        (dangerous permission set size)
    OB  — Obfuscation axis            (DexClassLoader + reflection + entropy)
    IR  — Infrastructure Risk axis    (hardcoded URLs / IPs)

All components are normalized to 0–100 before applying weights.
Final score is capped at 100.
"""

import logging
import math
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Malware Family Severity Weights ─────────────────────────────────────────

FAMILY_BANKING_WEIGHT: Dict[str, float] = {
    "Drinik":    1.0,   # Primary Indian banking trojan — full weight
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

# ─── STEI — 5-Axis Formula (PDF Spec) ────────────────────────────────────────

def _axis_ct(flags: Dict[str, Any]) -> Tuple[float, List[str]]:
    """
    Credential Theft axis (weight 0.60).
    Captures the three primary credential-harvesting attack vectors.
    Score: 0–100.
    """
    evidence: List[str] = []
    score = 0.0

    # Accessibility service — OTP tap injection and screen scraping
    if flags.get("has_accessibility_abuse"):
        score += 40.0
        evidence.append("BIND_ACCESSIBILITY_SERVICE: screen-scraping / tap-injection vector (+40 CT)")

    # SMS interception — OTP theft
    if flags.get("has_sms_read_write"):
        score += 35.0
        evidence.append("READ/RECEIVE_SMS: OTP interception via SMS (+35 CT)")

    # Overlay windows — fake login phishing
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

    # Concealed payload — a nested APK/DEX or encrypted blob shipped as an asset.
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

    stei = (0.60 * ct) + (0.20 * bt) + (0.10 * pr) + (0.05 * ob) + (0.05 * ir)
    stei = round(min(stei, 100.0), 2)

    all_evidence = ct_ev + bt_ev + pr_ev + ob_ev + ir_ev
    by_axis = {"ct": ct_ev, "bt": bt_ev, "pr": pr_ev, "ob": ob_ev, "ir": ir_ev}
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
            "evidence": "BIND_ACCESSIBILITY_SERVICE — enables programmatic tap injection",
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
            "evidence": "READ_SMS / RECEIVE_SMS — bank OTP messages readable before user sees them",
            "confidence": 95,
        })

    if flags.get("has_system_alert_window"):
        rows.append({
            "indicator": "Overlay Window Capability",
            "threat_scenario": "Phishing Overlay — Fake Banking Login Screen",
            "overlay_risk": "Critical",
            "credential_theft_risk": "High",
            "c2_risk": "Low",
            "persistence_risk": "Medium",
            "evidence": "SYSTEM_ALERT_WINDOW — draws UI layer over any banking app",
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
            "threat_scenario": "Stage-2 Payload Drop — Evades Static Scanners",
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
            "threat_scenario": "Native Code Execution — Bypasses Java Analysis",
            "overlay_risk": "Low",
            "credential_theft_risk": "Medium",
            "c2_risk": "Medium",
            "persistence_risk": "High",
            "evidence": "System.loadLibrary — loads .so native binary at runtime",
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
    "accessibility": 0.35,   # wa — present in 87% of banking trojans (ThreatFabric 2024)
    "sms":           0.25,   # ws — OTP interception
    "overlay":       0.20,   # wo — phishing overlay attacks
    "banking":       0.10,   # wb — confirms banking app targeting
    "network":       0.05,   # wn — C2 communication
    "persistence":   0.05,   # wp — device admin / lockdown
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
            logger.warning(f"[RiskEngine] Non-numeric {field}={value!r} — treated as 0.0")
        return 0.0

    if not math.isfinite(score):
        logger.warning(f"[RiskEngine] Non-finite {field}={value!r} — treated as 0.0")
        return 0.0

    if score < lo or score > hi:
        logger.warning(f"[RiskEngine] {field}={score} outside [{lo}, {hi}] — clamped")
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
    # Validate at the boundary — see _coerce_score. The sandbox is the only
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
_MIN_DYNAMIC_EVENTS = 3


def _dynamic_run_was_conclusive(dynamic: Optional[Dict]) -> bool:
    """
    Did the sandbox actually observe enough to reason about?
    
    A run is conclusive if Frida attached cleanly, hooks loaded, and actual
    behavior was observed (events captured or BFCI >= 20.0). Runs where no
    behavior was observed, or where instrumentation failed, are inconclusive.
    """
    if not dynamic or not dynamic.get("available", False):
        return False

    status = str(dynamic.get("dynamic_status") or "").upper()
    outcome = str(dynamic.get("outcome") or "").upper()

    if status in {"NO_BEHAVIOR_OBSERVED", "INSTRUMENTATION_FAILED", "TIMEOUT", "FAILED"} or outcome == "FAILED":
        return False

    # Count only fields that record what the SAMPLE did.
    #
    # Two defects lived here, and together they made evasion pay:
    #
    #   1. `evidence` was counted. That field carries harness commentary
    #      ("process started"), not sample behaviour — so a trojan that
    #      detected Frida and deliberately did nothing still produced one
    #      "observed" item and was rated CONCLUSIVE.
    #   2. The threshold was `>= 1`, while _MIN_DYNAMIC_EVENTS (=3) sat
    #      directly above this function, unused. The declared policy and the
    #      implemented policy disagreed.
    #
    # Consequence: a dormant sample took the dynamic axis — the LARGEST weight
    # at 0.35 — at a near-zero value, diluting strong static evidence. Measured
    # on the regression fixture, a trojan scoring 42.22 static-only dropped to
    # 23.75 after a sandbox run that observed nothing. The better a sample's
    # evasion, the safer this engine rated it, which is precisely the regression
    # the surrounding comment says was fixed.
    observed = 0
    for field in ("api_calls", "network_logs", "activities_triggered",
                  "files_accessed"):
        value = dynamic.get(field)
        try:
            observed += len(value or [])
        except TypeError:
            continue
    if observed >= _MIN_DYNAMIC_EVENTS:
        return True

    try:
        return float(dynamic.get("bfci") or 0.0) >= 20.0
    except (TypeError, ValueError):
        return False




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
        return 0.0, ["Dynamic analysis not available — using static-only mode"]

    engine = dynamic.get("engine", "mobsf")

    # ── Frida path: proper BFCI formula ───────────────────────────────────────
    if engine == "frida":
        return _calculate_bfci_from_frida(dynamic)

    # ── MobSF path: flat-bonus approximation ──────────────────────────────────
    score = 0.0
    evidence: List[str] = []

    api_calls_str = str(dynamic.get("api_calls", []))

    # Accessibility (wa = 0.35 → maps to +35 at full confidence)
    if "accessibilityservice" in api_calls_str.lower():
        score += 35.0
        evidence.append("Runtime Accessibility abuse confirmed — MobSF (BFCI component A, wa=0.35, +35)")

    # SMS interception (ws = 0.25 → +25)
    if "readtext" in api_calls_str.lower() or "sms" in api_calls_str.lower():
        score += 25.0
        evidence.append("Runtime SMS/OTP interception confirmed — MobSF (BFCI component S, ws=0.25, +25)")

    # Overlay (wo = 0.20 → +20)
    if "windowmanager" in api_calls_str.lower() or "overlay" in api_calls_str.lower():
        score += 20.0
        evidence.append("Runtime overlay window confirmed — MobSF (BFCI component O, wo=0.20, +20)")

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

    # Screenshots — not in BFCI formula, added as bonus
    screenshots = dynamic.get("screenshots", [])
    if screenshots:
        score += 10.0
        evidence.append(f"Screen capture observed — {len(screenshots)} screenshot(s) (+10 bonus)")

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
        evidence.append("Unknown family — moderate banking impact assumed (+20)")

    # Regulatory risk — banks are mandated to act on these
    if flags.get("has_sms_read_write") and flags.get("targets_indian_banks"):
        score += 20.0
        evidence.append("RBI MDS-2021 OTP interception violation — regulatory risk (+20)")

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
    dynamic_available = dynamic_result is not None and dynamic_result.get("available", False)

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
    # The author already knew this pattern — the old code redistributed the
    # dynamic weight — it just was not applied to correlation.
    correlation_available = bool(correlation_result and correlation_result.get("available"))

    # A sandbox run that observed nothing is INCONCLUSIVE, not clean.
    #
    # Evasive malware is built to stay dormant under analysis — banking trojans
    # routinely fingerprint ADB, Frida and emulator properties and suppress
    # behaviour. Scoring "no events captured" as a near-zero dynamic value meant
    # the axis with the LARGEST weight actively diluted strong static evidence,
    # so the better a sample's evasion, the safer this engine rated it.
    #
    # Measured on Cerberus: static-only 38.74 "Suspicious"; after a 30 s run that
    # captured 0 API calls and 0 network events, the dynamic axis took 0.437 of
    # the weight at a value of 5.0 and pulled the verdict down to 23.98 "Safe".
    #
    # This is NOT "dynamic may only ever raise the score" — a run with real
    # coverage that observes benign behaviour is legitimate evidence and still
    # lowers it. The distinction is whether the sandbox actually observed
    # anything to reason about.
    dynamic_conclusive = dynamic_available and _dynamic_run_was_conclusive(dynamic_result)

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

    # CH06 / VIDE deterministic escalations (P1: cluster required for visual-only)
    vide_evidence: List[str] = []
    if vide_result:
        for line in (vide_result.get("vide_compare") or {}).get("evidence_lines") or []:
            vide_evidence.append(line)
        for line in (vide_result.get("signer_impersonation") or {}).get("evidence_lines") or []:
            vide_evidence.append(line)
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

    if vide_result and vide_result.get("signer_impersonation", {}).get("detected"):
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
    # This does NOT assert the sample is malicious — the score is left untouched.
    # It refuses to certify as safe something that was never actually analysed,
    # and says so in the evidence. Dynamic analysis, which sees the unpacked
    # payload, is what resolves the ambiguity; if it ran, the score stands on its
    # own and no floor is applied.
    visibility_floored = False
    if band == "Safe" and not dynamic_conclusive and flags_dict.get("has_concealed_payload"):
        band = "Suspicious"
        visibility_floored = True
        stei_evidence.append(
            "VERDICT FLOORED: payload is concealed and no dynamic analysis was "
            "available, so static analysis could not observe the code that will "
            "actually run. Not rated Safe — run dynamic analysis to resolve."
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
    confidence = min(confidence, 99.0)

    all_evidence = stei_evidence + dynamic_evidence + corr_evidence + banking_evidence + vide_evidence

    return {
        # Legacy fields (keep backward compat)
        "base_score": base_score,
        "ai_confidence_multiplier": round(ai_multiplier, 2),
        "final_risk_score": final_rounded,
        "risk_band": band,

        # Full FRS breakdown with 5-axis STEI
        "frs_breakdown": {
            "stei": round(stei, 2),
            "dynamic": round(dynamic_score, 2),
            "correlation": round(correlation_score, 2),
            "banking_impact": round(banking_score, 2),
            "formula_used": "full_frs" if dynamic_available else "static_only_frs",
            # Which axes actually contributed, and at what renormalised weight.
            # An excluded axis is one with no data — it is not scored as benign.
            "axes_used": axes_used,
            "axes_excluded": axes_excluded,
            "concealed_payload": bool(flags_dict.get("has_concealed_payload")),
            "dynamic_ran": dynamic_available,
            "dynamic_conclusive": dynamic_conclusive,
            "verdict_floored_for_visibility": visibility_floored,
            "dynamic_available": dynamic_available,
            # 5-axis STEI breakdown
            "stei_axes": {
                "ct": stei_axes.get("ct", 0.0),
                "bt": stei_axes.get("bt", 0.0),
                "pr": stei_axes.get("pr", 0.0),
                "ob": stei_axes.get("ob", 0.0),
                "ir": stei_axes.get("ir", 0.0),
            },
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
    if band == "Critical":
        if family != "Unknown":
            return f"IMMEDIATE BLOCK — {family} confirmed. Isolate all affected devices. Engage IR team. Issue customer advisory per RBI CPG-2022."
        return "IMMEDIATE BLOCK — Critical behavioral signature. Isolate devices, revoke banking sessions, escalate to CISO."
    if band == "High Risk":
        return "BLOCK & INVESTIGATE — Do not deploy. Submit to dynamic sandbox. Notify SOC lead. Consider customer advisory."
    if band == "Suspicious":
        return "QUARANTINE — Further analysis required. Do not approve for enterprise deployment. Monitor network traffic."
    return "MONITOR — Low risk. Approved for deployment under standard monitoring. Re-scan on next version update."
