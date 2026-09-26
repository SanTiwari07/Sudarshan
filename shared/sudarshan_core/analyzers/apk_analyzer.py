import logging
import math
import os
import zipfile
import re
from typing import List, Tuple
try:
    from androguard.misc import AnalyzeAPK
    import loguru
    loguru.logger.disable("androguard")
except ImportError:
    # Host environments without androguard installed. The name is kept bound so
    # the module still imports (callers that only want the constants above, and
    # every test that monkeypatches AnalyzeAPK, must keep working) - but
    # analyze_apk() refuses to run rather than letting the None propagate.
    AnalyzeAPK = None

from sudarshan_core.models.schemas import AndroguardOutput, StaticAnalysisFlags

logger = logging.getLogger(__name__)

INDIAN_BANK_PACKAGES = [
    "com.boi", "com.sbi", "com.icici", "com.hdfc", "com.axis",
    "com.pnb", "com.kotak", "com.canara", "com.unionbank", "com.bankofindia",
    "com.aubank", "com.idfcfirstbank", "com.rblbank", "com.yesbank",
    "com.indusind", "com.federalbank", "com.southindianbank", "com.karnataka",
    "com.npci", "com.bhimupi", "in.org.npci.upiapp",
]

# Dangerous API detection - REPORTED names.
#
# These were previously matched with `if name in method.get_name()`, against a
# method name, which never contains a dot. So "Runtime.exec",
# "ProcessBuilder.start" and "System.loadLibrary" could not match anything: half
# this list was dead, and it is consumed by the scoring engine
# (risk_engine._axis_ob checks for "System.loadLibrary", classification_engine
# checks for "Runtime.exec" and "DexClassLoader").
#
# Detection now matches the bare method name AND its defining class - see
# analyze_apk. The names below are the labels the rest of the system expects and
# must not be renamed.
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

def _matches_package(haystack: str, package: str) -> bool:
    """
    True when `haystack` references `package` as a package name, not merely as
    a substring.

    A package reference must end at a component boundary: end-of-string, a '/'
    (as in a component name "com.sbi.app/.MainActivity"), or a character that
    cannot continue an identifier. Without this, "com.sbi" matched
    "com.sbidiagnostics" and "in.example.com.sbin" - false Banking-Targeting
    hits that carry 20% of STEI plus a +20 regulatory bonus.
    """
    idx = 0
    plen = len(package)
    while True:
        idx = haystack.find(package, idx)
        if idx == -1:
            return False
        after = haystack[idx + plen] if idx + plen < len(haystack) else ""
        before = haystack[idx - 1] if idx > 0 else ""
        # The char after must not continue the identifier. A following '.' IS
        # allowed (com.sbi.lotusintouch is a real match for com.sbi).
        after_ok = (after == "" or after == "." or not (after.isalnum() or after == "_"))
        # The char before must not be an identifier char either, so
        # "mycom.sbi" does not match "com.sbi".
        before_ok = (before == "" or not (before.isalnum() or before == "_" or before == "."))
        if after_ok and before_ok:
            return True
        idx += 1


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

    Never raises - a manifest that fails to parse must degrade to False rather
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

      1. A nested executable - an APK or DEX shipped as a resource/asset rather
         than as a top-level classes*.dex.
      2. A max-entropy blob (encrypted) that is large relative to the primary
         classes.dex, i.e. the real code is not the code you can read.

    Measured on the labelled corpus this fired on 5/8 banking trojans
    (Anubis, Drinik, FluBot, Hook, Octo) and 0/9 non-malware samples
    (4 legitimate apps, 4 OWASP crackmes, 1 deliberately vulnerable app).
    That corpus is small - this is a measured signal, not a proven one.

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
                        f"Nested {kind} concealed at '{name}' ({info.file_size // 1024} KB) - "
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
                        f"vs {primary // 1024} KB classes.dex - payload likely unpacked at runtime"
                    )
    except Exception as exc:
        # A malformed archive is NOT evidence of safety.
        #
        # This used to return (False, []) - "no concealment detected" - for any
        # exception, including the one that matters most: a deliberately
        # corrupted ZIP. Samples malform their own archive precisely to break
        # static parsers, so the parse failure IS the signal. Reporting it as
        # "clean" inverted the meaning of the strongest concealment indicator.
        logger.warning(
            "[APKAnalyzer] Archive could not be parsed for concealment analysis "
            "(%s: %s) - treating the parse failure itself as a concealment signal.",
            type(exc).__name__, exc,
        )
        return True, [
            f"Archive structure could not be parsed ({type(exc).__name__}) - "
            f"malformed or deliberately corrupted ZIP, which defeats static "
            f"inspection of the payload"
        ]

    return bool(evidence), evidence[:5]


def analyze_apk(apk_path: str) -> AndroguardOutput:
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK not found: {apk_path}")

    # Say which dependency is missing. Without this the ImportError fallback
    # above surfaces as "TypeError: 'NoneType' object is not callable" from
    # inside the analyser - a stack trace that names neither androguard nor the
    # fix, and that a caller catching Exception can mistake for a malformed
    # APK. A missing analysis engine is an environment fault, not a finding
    # about the sample, and must never be reported as one.
    if AnalyzeAPK is None:
        raise RuntimeError(
            "androguard is not installed, so static analysis cannot run. "
            "Install it with `pip install androguard` (or `pip install -e shared`) "
            "and re-run. This is an environment fault - it says nothing about "
            f"the sample at {apk_path}."
        )

    a, d, dx = AnalyzeAPK(apk_path)

    package_name = a.get_package()
    if not package_name or package_name in ("Failed", "Unknown", "None"):
        # Fallback to reading AndroidManifest.xml from ZIP using regex
        try:
            with zipfile.ZipFile(apk_path) as z:
                if "AndroidManifest.xml" in z.namelist():
                    raw = z.read("AndroidManifest.xml")
                    matches = re.findall(rb'[a-zA-Z][a-zA-Z0-9_]*\.[a-zA-Z0-9_.]+', raw)
                    for match in matches:
                        decoded = match.decode('ascii', errors='ignore')
                        if len(decoded) > 5 and "." in decoded and not decoded.startswith("android.") and not decoded.startswith("schemas.") and decoded not in ("Failed", "Unknown", "None"):
                            package_name = decoded
                            break
        except Exception:
            pass

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
    # eight banking trojans - including Cerberus, Octo, SharkBot and Teabot,
    # which all declare it - while accessibility abuse is the single
    # highest-weighted signal in the CT axis (BFCI weight 0.35).
    flags.has_accessibility_abuse = _detects_accessibility_service(a)

    # ── 2. String & Constant Analysis ─────────────────────────────────────────
    strings_fired: List[str] = []
    all_strings:   List[str] = []
    seen_urls:     set       = set()

    if d:
        for dex_obj in d:
            if not hasattr(dex_obj, "get_strings"):
                continue
            for string_data in dex_obj.get_strings():
                s = string_data.decode("utf-8", errors="ignore") if isinstance(string_data, bytes) else str(string_data)
                all_strings.append(s)

                # URL / IP detection.
                # Deduplicated: the Infrastructure Risk axis scores
                # `len(hardcoded_urls_ips) * 10`, so the same C2 string
                # appearing ten times in the string pool used to score
                # identically to ten DISTINCT endpoints.
                if URL_REGEX.search(s) or IP_REGEX.search(s):
                    if len(s) < 256 and s not in seen_urls:
                        seen_urls.add(s)
                        flags.hardcoded_urls_ips.append(s)
                        if s not in strings_fired:
                            strings_fired.append(s)

                # Indian bank package detection.
                # Matched on a package-name BOUNDARY, not as a bare substring:
                # "com.sbi" previously matched "com.sbidiagnostics",
                # "example.com.sbin" and any string that merely contained it.
                # This feeds the BT axis (20% of STEI) and gates a +20
                # regulatory bonus in banking impact, so a false hit is
                # expensive.
                for bank_pkg in INDIAN_BANK_PACKAGES:
                    if _matches_package(s, bank_pkg):
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
        # Match on the DEFINING CLASS as well as the method name where the class
        # is what disambiguates. `exec` and `start` are common method names; only
        # java.lang.Runtime.exec and java.lang.ProcessBuilder.start are the APIs
        # we mean, and matching the bare name alone would flag every app with a
        # method called start().
        _CLASS_QUALIFIED = {
            "Runtime.exec":         ("Ljava/lang/Runtime;", "exec"),
            "ProcessBuilder.start": ("Ljava/lang/ProcessBuilder;", "start"),
            "System.loadLibrary":   ("Ljava/lang/System;", "loadLibrary"),
        }

        found = set(flags.dangerous_apis_found)
        for method in dx.get_methods():
            m = method.get_method()
            try:
                method_name = m.get_name()
                class_name = m.get_class_name()
            except Exception:
                continue

            for reported, (want_class, want_method) in _CLASS_QUALIFIED.items():
                if reported in found:
                    continue
                if method_name == want_method and want_class in class_name:
                    found.add(reported)

            # Name-only matchers (unambiguous identifiers).
            for reported in ("addJavascriptInterface", "DexClassLoader", "PathClassLoader"):
                if reported not in found and reported in method_name:
                    found.add(reported)

            # Reflection detection
            if not flags.has_reflection:
                for ref_api in REFLECTION_APIS:
                    if ref_api in method_name:
                        flags.has_reflection = True
                        break

        # Cross-reference scan: an app CALLING Runtime.exec does not necessarily
        # DEFINE a method named exec, so the loop above (which walks defined
        # methods) can miss real usage. Androguard exposes the external methods
        # a DEX references - that is where an invoked platform API shows up.
        try:
            for ext in dx.get_external_classes():
                cls = ext.get_vm_class().get_name() if hasattr(ext, "get_vm_class") else str(ext)
                for meth in ext.get_methods():
                    try:
                        name = meth.get_name()
                    except Exception:
                        continue
                    for reported, (want_class, want_method) in _CLASS_QUALIFIED.items():
                        if name == want_method and want_class in str(cls):
                            found.add(reported)
                    for reported in ("addJavascriptInterface", "DexClassLoader", "PathClassLoader"):
                        if reported in name or reported in str(cls):
                            found.add(reported)
        except Exception as exc:
            # Never fail the analysis over an optional enrichment pass.
            pass

        flags.dangerous_apis_found = sorted(found)

    # The user-facing name from the manifest. Resolving it goes through the
    # resource table, which malformed or deliberately corrupted APKs routinely
    # break, so a failure here yields "" rather than losing the whole analysis.
    try:
        app_label = a.get_app_name() or ""
    except Exception as exc:
        logger.debug("[apk_analyzer] Could not resolve app label: %s", exc)
        app_label = ""

    apk_size = None
    try:
        size_bytes = os.path.getsize(apk_path)
        apk_size = f"{size_bytes / (1024 * 1024):.1f} MB"
    except Exception:
        pass

    version_name = None
    try:
        version_name = a.get_androidversion_name()
    except Exception:
        pass

    return AndroguardOutput(
        package_name=package_name if package_name else "Unknown",
        permissions=permissions if permissions else [],
        flags=flags,
        suspicious_strings=strings_fired[:50],
        app_label=app_label,
        version_name=version_name,
        apk_size=apk_size,
    )
