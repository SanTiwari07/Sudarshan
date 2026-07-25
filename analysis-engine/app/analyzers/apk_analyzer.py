import math
import os
import re
from typing import List, Tuple
try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    AnalyzeAPK = None  # Fallback for host environments without androguard installed

from app.models.schemas import AndroguardOutput, StaticAnalysisFlags

INDIAN_BANK_PACKAGES = [
    "com.boi", "com.sbi", "com.icici", "com.hdfc", "com.axis",
    "com.pnb", "com.kotak", "com.canara", "com.unionbank", "com.bankofindia",
    "com.aubank", "com.idfcfirstbank", "com.rblbank", "com.yesbank",
    "com.indusind", "com.federalbank", "com.southindianbank", "com.karnataka",
    "com.npci", "com.bhimupi", "in.org.npci.upiapp",
]

DANGEROUS_APIS = [
    "addJavascriptInterface", "Runtime.exec", "ProcessBuilder.start",
    "DexClassLoader", "PathClassLoader", "System.loadLibrary",
]

# Reflection APIs that indicate obfuscation / dynamic invocation
REFLECTION_APIS = [
    "forName", "getDeclaredMethod", "getDeclaredField", "getDeclaredConstructor",
    "invoke", "newInstance", "setAccessible",
]

URL_REGEX = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
IP_REGEX  = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')


# ─── Shannon Entropy ──────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string (0.0 low, 1.0 high uniformity)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    entropy = -sum((c / n) * math.log2(c / n) for c in freq.values())
    # Normalise to [0, 1] relative to max possible entropy = log2(n)
    max_entropy = math.log2(n) if n > 1 else 1.0
    return min(entropy / max_entropy, 1.0) if max_entropy > 0 else 0.0


def _mean_string_entropy(strings: List[str]) -> float:
    """Average entropy across a sample of non-trivial strings."""
    candidates = [s for s in strings if len(s) > 6 and not s.startswith("http")][:200]
    if not candidates:
        return 0.0
    return sum(_shannon_entropy(s) for s in candidates) / len(candidates)


# ─── Main Analyzer ────────────────────────────────────────────────────────────

def analyze_apk(apk_path: str) -> AndroguardOutput:
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    a, d, dx = AnalyzeAPK(apk_path)

    package_name = a.get_package()
    permissions  = a.get_permissions()

    flags = StaticAnalysisFlags()

    # ── 1. Permission Analysis ────────────────────────────────────────────────
    for perm in permissions:
        if "BIND_ACCESSIBILITY_SERVICE" in perm:
            flags.has_accessibility_abuse = True
        if "READ_SMS" in perm or "RECEIVE_SMS" in perm or "SEND_SMS" in perm:
            flags.has_sms_read_write = True
        if "SYSTEM_ALERT_WINDOW" in perm:
            flags.has_system_alert_window = True

    # ── 2. String & Constant Analysis ─────────────────────────────────────────
    strings_fired: List[str] = []
    all_strings:   List[str] = []

    if d:
        for dex_obj in d:
            if not hasattr(dex_obj, "get_strings"):
                continue
            for string_data in dex_obj.get_strings():
                s = string_data.decode("utf-8", errors="ignore") if isinstance(string_data, bytes) else str(string_data)
                all_strings.append(s)

                # URL / IP detection
                if URL_REGEX.search(s) or IP_REGEX.search(s):
                    if len(s) < 256:
                        flags.hardcoded_urls_ips.append(s)
                        if s not in strings_fired:
                            strings_fired.append(s)

                # Indian bank package detection
                for bank_pkg in INDIAN_BANK_PACKAGES:
                    if bank_pkg in s:
                        flags.targets_indian_banks = True
                        if bank_pkg not in flags.indian_bank_packages_found:
                            flags.indian_bank_packages_found.append(bank_pkg)
                        if s not in strings_fired and len(s) < 100:
                            strings_fired.append(s)

    # ── 3. Obfuscation / Entropy ──────────────────────────────────────────────
    flags.obfuscation_score = round(_mean_string_entropy(all_strings), 4)

    # ── 4. API & Reflection Analysis ──────────────────────────────────────────
    if dx:
        for method in dx.get_methods():
            method_name = method.get_method().get_name()

            # Dangerous API detection
            for dangerous_api in DANGEROUS_APIS:
                if dangerous_api in method_name:
                    if dangerous_api not in flags.dangerous_apis_found:
                        flags.dangerous_apis_found.append(dangerous_api)

            # Reflection detection
            if not flags.has_reflection:
                for ref_api in REFLECTION_APIS:
                    if ref_api in method_name:
                        flags.has_reflection = True
                        break

    return AndroguardOutput(
        package_name=package_name if package_name else "Unknown",
        permissions=permissions if permissions else [],
        flags=flags,
        suspicious_strings=strings_fired[:50],
    )
