import math
import os
import zipfile
import re
from typing import List, Tuple
try:
    from androguard.misc import AnalyzeAPK
except ImportError:
    AnalyzeAPK = None  # Fallback for host environments without androguard installed

from sudarshan_core.models.schemas import AndroguardOutput, StaticAnalysisFlags

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

_ACCESSIBILITY_MARKERS = (
    "BIND_ACCESSIBILITY_SERVICE",                        # <service android:permission=…>
    "android.accessibilityservice.AccessibilityService",  # intent-filter action
    "android.accessibilityservice",                       # meta-data resource
)


def _detects_accessibility_service(apk) -> bool:
    """
    True when the APK declares an AccessibilityService.

    Checks three independent places, because a sample only needs one of them and
    obfuscators routinely strip or rename the others:

      1. androguard's parsed <service> declarations and their guard permission
      2. declared intent-filter actions
      3. the raw decoded manifest, as a last-resort substring match

    Never raises — a manifest that fails to parse must degrade to False rather
    than abort the whole analysis.
    """
    # 1. Parsed service declarations
    try:
        for svc in apk.get_services() or []:
            details = apk.get_element("service", "permission", name=svc) or ""
            if "BIND_ACCESSIBILITY_SERVICE" in str(details).upper():
                return True
    except Exception:
        pass

    # 2. Declared intent-filter actions
    try:
        for svc in apk.get_services() or []:
            for action in apk.get_intent_filters("service", svc).get("action", []):
                if "accessibilityservice" in action.lower():
                    return True
    except Exception:
        pass

    # 3. Raw manifest substring match
    try:
        xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", errors="replace")
        return any(m.lower() in xml.lower() for m in _ACCESSIBILITY_MARKERS)
    except Exception:
        return False


_APK_MAGIC = b"PK\x03\x04"
_DEX_MAGIC = b"dex\n"

# Below this, a blob is too small to be a meaningful hidden payload.
_MIN_PAYLOAD_BYTES = 64 * 1024
# Shannon entropy per byte, normalised 0–1. >0.95 means encrypted/compressed.
_ENCRYPTED_ENTROPY = 0.95


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c) / 8.0


def _detect_concealed_payload(apk_path: str) -> Tuple[bool, List[str]]:
    """
    Detect a payload hidden inside the APK rather than declared in it.

    Two principled indicators, both of which legitimate apps have no reason to
    exhibit:

      1. A nested executable — an APK or DEX shipped as a resource/asset rather
         than as a top-level classes*.dex.
      2. A max-entropy blob (encrypted) that is large relative to the primary
         classes.dex, i.e. the real code is not the code you can read.

    Measured on the labelled corpus this fired on 5/8 banking trojans
    (Anubis, Drinik, FluBot, Hook, Octo) and 0/9 non-malware samples
    (4 legitimate apps, 4 OWASP crackmes, 1 deliberately vulnerable app).
    That corpus is small — this is a measured signal, not a proven one.

    Never raises: a malformed archive degrades to "not detected".
    """
    evidence: List[str] = []
    try:
        with zipfile.ZipFile(apk_path) as z:
            names = z.namelist()
            try:
                primary = z.getinfo("classes.dex").file_size
            except KeyError:
                primary = 0

            for name in names:
                try:
                    info = z.getinfo(name)
                except KeyError:
                    continue
                if info.file_size < _MIN_PAYLOAD_BYTES:
                    continue
                # A top-level classes*.dex is normal multidex, not concealment.
                if name.endswith(".dex") and "/" not in name:
                    continue

                try:
                    with z.open(name) as fh:
                        head = fh.read(8)
                except Exception:
                    continue

                if head.startswith(_APK_MAGIC) or head.startswith(_DEX_MAGIC):
                    kind = "APK" if head.startswith(_APK_MAGIC) else "DEX"
                    evidence.append(
                        f"Nested {kind} concealed at '{name}' ({info.file_size // 1024} KB) — "
                        "executable payload shipped as a resource"
                    )
                    continue

                try:
                    with z.open(name) as fh:
                        sample = fh.read(65536)
                except Exception:
                    continue

                ent = _byte_entropy(sample)
                if ent > _ENCRYPTED_ENTROPY and info.file_size > max(primary * 0.25, _MIN_PAYLOAD_BYTES):
                    evidence.append(
                        f"Encrypted blob '{name}' ({info.file_size // 1024} KB, entropy {ent:.2f}) "
                        f"vs {primary // 1024} KB classes.dex — payload likely unpacked at runtime"
                    )
    except Exception:
        return False, []

    return bool(evidence), evidence[:5]


def analyze_apk(apk_path: str) -> AndroguardOutput:
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    a, d, dx = AnalyzeAPK(apk_path)

    package_name = a.get_package()
    permissions  = a.get_permissions()

    flags = StaticAnalysisFlags()

    # ── 1. Permission Analysis ────────────────────────────────────────────────
    for perm in permissions:
        if "READ_SMS" in perm or "RECEIVE_SMS" in perm or "SEND_SMS" in perm:
            flags.has_sms_read_write = True
        if "SYSTEM_ALERT_WINDOW" in perm:
            flags.has_system_alert_window = True

    # ── 1b. Accessibility-service abuse ───────────────────────────────────────
    # BIND_ACCESSIBILITY_SERVICE is NOT a <uses-permission>. It is the guard
    # attribute on the <service> element that Android requires an accessibility
    # service to declare:
    #
    #   <service android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE">
    #     <intent-filter>
    #       <action android:name="android.accessibilityservice.AccessibilityService"/>
    #
    # The previous check scanned get_permissions() for that string, so it could
    # never fire. Measured against the labelled corpus it returned False for all
    # eight banking trojans — including Cerberus, Octo, SharkBot and Teabot,
    # which all declare it — while accessibility abuse is the single
    # highest-weighted signal in the CT axis (BFCI weight 0.35).
    flags.has_accessibility_abuse = _detects_accessibility_service(a)

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

    # ── 3b. Packer / dropper concealment ──────────────────────────────────────
    flags.has_concealed_payload, flags.concealment_evidence = _detect_concealed_payload(apk_path)

    # A dropper's manifest is deliberately uninformative. Flag the case where a
    # low score reflects poor visibility rather than genuine safety, so the
    # verdict can be qualified downstream instead of reading as a clean bill.
    flags.limited_static_visibility = bool(
        flags.has_concealed_payload and len(permissions) <= 6
    )

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
