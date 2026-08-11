"""
Sandbox device discovery, provider fingerprinting, and selection.

The rest of Sudarshan talks to a selected SandboxDevice (serial + metadata).
Provider-specific behaviour stays in GenymotionProvider / AndroidAvdProvider /
PhysicalDeviceProvider adapters - not scattered through the DAE.
"""

from __future__ import annotations

import logging
import re
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from sudarshan_core.sandbox.types import DeviceInfo, TransportType

logger = logging.getLogger(__name__)

# Canonical provider ids used in DeviceInfo.provider / SandboxConfig.provider
PROVIDER_GENYMOTION = "genymotion"
PROVIDER_ANDROID_AVD = "android_avd"
PROVIDER_PHYSICAL = "physical"
PROVIDER_UNKNOWN = "unknown"

PROVIDER_DISPLAY = {
    PROVIDER_GENYMOTION: "Genymotion",
    PROVIDER_ANDROID_AVD: "Android Studio AVD",
    PROVIDER_PHYSICAL: "Physical device",
    PROVIDER_UNKNOWN: "Unknown",
    # Legacy alias kept for logs / older configs
    "android_studio": "Android Studio AVD",
}

_GENYMOTION_MARKERS = re.compile(
    r"genymotion|vbox86|vbox86p|vbox86tp|genymobile",
    re.IGNORECASE,
)
_AVD_MARKERS = re.compile(
    r"sdk_gphone|google_sdk|emulator|ranchu|goldfish|aosp_x86|sdk_phone",
    re.IGNORECASE,
)


def transport_for_serial(serial: str) -> TransportType:
    """Classify ADB transport from the device serial string."""
    s = (serial or "").strip()
    if not s:
        return "unknown"
    if s.startswith("emulator-"):
        return "emulator"
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$", s):
        return "tcp"
    if ":" in s and not s.startswith("usb:"):
        # host:port style (may be hostname)
        return "tcp"
    return "usb"


def ip_from_serial(serial: str) -> str:
    """Extract IP/host from an IP:port serial; empty otherwise."""
    s = (serial or "").strip()
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$", s):
        return s.split(":", 1)[0]
    return ""


def detect_provider_from_props(
    *,
    serial: str,
    manufacturer: str = "",
    model: str = "",
    device: str = "",
    product: str = "",
    fingerprint: str = "",
    hardware: str = "",
    qemu: str = "",
    extra_blob: str = "",
) -> str:
    """
    Infer sandbox provider from Android properties / serial.

    Prefer property fingerprints over hardcoded IPs. Uncertain devices that
    still look like stock emulators become android_avd; otherwise physical.
    """
    blob = " ".join(
        [
            serial or "",
            manufacturer or "",
            model or "",
            device or "",
            product or "",
            fingerprint or "",
            hardware or "",
            qemu or "",
            extra_blob or "",
        ]
    )

    if _GENYMOTION_MARKERS.search(blob) or (manufacturer or "").lower() == "genymotion":
        return PROVIDER_GENYMOTION

    if serial.startswith("emulator-"):
        return PROVIDER_ANDROID_AVD

    if _AVD_MARKERS.search(blob) or (qemu or "").strip() in ("1", "true"):
        return PROVIDER_ANDROID_AVD

    # TCP serials on VirtualBox host-only ranges are often Genymotion even when
    # props are sparse - use as a weak hint only when product looks like vbox.
    if transport_for_serial(serial) == "tcp" and re.search(
        r"vbox|geny", blob, re.IGNORECASE
    ):
        return PROVIDER_GENYMOTION

    if transport_for_serial(serial) == "emulator":
        return PROVIDER_ANDROID_AVD

    # Physical USB / unknown TCP without emulator markers
    if transport_for_serial(serial) in ("usb", "tcp", "unknown"):
        # Avoid classifying empty-prop TCP as physical when it is clearly an emu IP
        if serial.startswith("emulator-"):
            return PROVIDER_ANDROID_AVD
        return PROVIDER_PHYSICAL

    return PROVIDER_UNKNOWN


def parse_adb_devices_l(output: str) -> List[Dict[str, str]]:
    """
    Parse `adb devices -l` into raw device dicts.

    Example line:
      emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64 ...
      192.168.56.102:5555    device product:vbox86p model:Phone ...
    """
    devices: List[Dict[str, str]] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("list of devices"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        serial, state = parts[0], parts[1]
        if state != "device":
            continue
        meta: Dict[str, str] = {"serial": serial, "state": state}
        for token in parts[2:]:
            if ":" in token:
                k, v = token.split(":", 1)
                meta[k] = v
        devices.append(meta)
    return devices


def enrich_device_info(
    base: DeviceInfo,
    *,
    props: Optional[Dict[str, str]] = None,
    adb_meta: Optional[Dict[str, str]] = None,
) -> DeviceInfo:
    """Fill transport / provider / AVD fields from props + `adb devices -l` meta."""
    props = props or {}
    adb_meta = adb_meta or {}

    manufacturer = props.get("manufacturer") or base.manufacturer or ""
    model = props.get("model") or base.model or adb_meta.get("model", "")
    product = props.get("product") or adb_meta.get("product", "")
    device_codename = props.get("device") or adb_meta.get("device", "")
    fingerprint = props.get("fingerprint", "")
    hardware = props.get("hardware", "")
    qemu = props.get("qemu", "")
    avd_name = props.get("avd_name") or props.get("qemu_avd") or ""

    provider = detect_provider_from_props(
        serial=base.serial,
        manufacturer=manufacturer,
        model=model,
        device=device_codename,
        product=product,
        fingerprint=fingerprint,
        hardware=hardware,
        qemu=qemu,
    )

    transport = transport_for_serial(base.serial)
    ip = base.ip or ip_from_serial(base.serial)

    base.provider = provider
    base.transport = transport
    base.ip = ip
    base.manufacturer = manufacturer or base.manufacturer
    base.model = model or base.model
    base.android_version = props.get("android_version") or base.android_version
    base.api_level = props.get("api_level") or base.api_level
    base.abi = props.get("abi") or base.abi
    base.abilist = props.get("abilist") or base.abilist
    base.is_emulator = provider in (PROVIDER_GENYMOTION, PROVIDER_ANDROID_AVD)
    base.avd_name = avd_name
    base.extra = {
        **(base.extra or {}),
        "product": product,
        "device": device_codename,
        "hardware": hardware,
        "fingerprint": fingerprint[:120] if fingerprint else "",
        **{k: v for k, v in adb_meta.items() if k not in ("serial", "state")},
    }
    return base


def provider_display_name(provider: str) -> str:
    return PROVIDER_DISPLAY.get(provider, provider or "Unknown")


def format_device_line(index: int, d: DeviceInfo) -> str:
    """Human-readable discovery line for startup logs."""
    label = provider_display_name(d.provider)
    abi = d.abi or "?"
    ver = d.android_version or "?"
    extra = f" — {d.avd_name}" if d.avd_name else ""
    return f"[{index}] {label} — {d.serial} — {abi} — Android {ver}{extra}"


def _frida_arch_supported(abi: str, supported_abis: Sequence[str]) -> bool:
    if not supported_abis:
        return True
    if not abi:
        return False
    abi_l = abi.lower()
    return any(abi_l == s.lower() or abi_l.startswith(s.lower()) for s in supported_abis)


def rank_devices(
    devices: Sequence[DeviceInfo],
    *,
    preferred_serial: str = "",
    preferred_provider: str = "",
    require_frida_abi: bool = False,
    supported_abis: Optional[Sequence[str]] = None,
) -> List[DeviceInfo]:
    """
    Deterministic ranking for sandbox selection.

    Priority:
      1. Exact preferred serial
      2. Preferred provider filter (when set and not auto)
      3. Emulator over physical
      4. Rooted / root-capable
      5. Frida ABI support (when known)
      6. Lexicographic serial (stable tie-break)
    """
    supported = list(supported_abis or [])

    def score(d: DeviceInfo) -> Tuple:
        serial_match = 0 if preferred_serial and d.serial == preferred_serial else 1
        provider_match = 0
        if preferred_provider and preferred_provider not in ("auto", ""):
            # Accept android_studio as alias of android_avd
            wanted = preferred_provider
            if wanted in ("android_studio", "androidstudio", "avd", "emulator"):
                wanted = PROVIDER_ANDROID_AVD
            provider_match = 0 if d.provider == wanted else 1
        is_emu = 0 if d.is_emulator or d.provider in (
            PROVIDER_GENYMOTION,
            PROVIDER_ANDROID_AVD,
        ) else 1
        rooted = 0 if d.rooted is True else (1 if d.rooted is None else 2)
        abi_ok = 0
        if require_frida_abi or supported:
            abi_ok = 0 if _frida_arch_supported(d.abi, supported) else 1
        return (serial_match, provider_match, is_emu, rooted, abi_ok, d.serial)

    return sorted(devices, key=score)


def select_sandbox_device(
    devices: Sequence[DeviceInfo],
    *,
    preferred_serial: str = "",
    preferred_provider: str = "",
    supported_abis: Optional[Sequence[str]] = None,
) -> DeviceInfo:
    """Select one device or raise ValueError with an actionable message."""
    if not devices:
        raise ValueError(
            "No Android sandbox detected. "
            "Start Genymotion or an Android Studio AVD, then run the bootstrap again."
        )

    if preferred_serial:
        for d in devices:
            if d.serial == preferred_serial:
                return d
        online = [d.serial for d in devices]
        logger.warning(
            "Configured device serial %r not found online (online: %s). Falling back to automatic selection.",
            preferred_serial,
            online,
        )

    ranked = rank_devices(
        devices,
        preferred_provider=preferred_provider,
        supported_abis=supported_abis,
    )
    chosen = ranked[0]
    if len(devices) > 1:
        logger.info(
            "Multiple Android devices detected. Selected: %s. "
            "Set ANDROID_DEVICE_SERIAL to override automatic selection.",
            chosen.serial,
        )
    return chosen


PropFetcher = Callable[[str, str], str]


def fetch_device_props(serial: str, getprop: PropFetcher) -> Dict[str, str]:
    """Fetch the Android properties used for enrichment / provider detection."""
    mapping = {
        "android_version": "ro.build.version.release",
        "api_level": "ro.build.version.sdk",
        "abi": "ro.product.cpu.abi",
        "abilist": "ro.product.cpu.abilist",
        "model": "ro.product.model",
        "manufacturer": "ro.product.manufacturer",
        "device": "ro.product.device",
        "product": "ro.build.product",
        "fingerprint": "ro.build.fingerprint",
        "hardware": "ro.hardware",
        "qemu": "ro.kernel.qemu",
        "avd_name": "ro.boot.qemu.avd_name",
        "qemu_avd": "ro.boot.qemu.avd_id",
    }
    out: Dict[str, str] = {}
    for key, prop in mapping.items():
        try:
            out[key] = (getprop(serial, prop) or "").strip()
        except Exception:  # noqa: BLE001
            out[key] = ""
    # Some AVDs expose the name only via this prop
    if not out.get("avd_name"):
        try:
            alt = (getprop(serial, "ro.boot.qemu.avd_name") or "").strip()
            if alt:
                out["avd_name"] = alt
        except Exception:  # noqa: BLE001
            pass
    return out


def normalize_provider_name(name: str) -> str:
    """Map config aliases to canonical provider ids."""
    n = (name or "").strip().lower()
    if n in ("", "auto"):
        return "auto"
    if n in ("android_studio", "androidstudio", "avd", "emulator", "android_avd"):
        return PROVIDER_ANDROID_AVD
    if n in ("genymotion", "geny"):
        return PROVIDER_GENYMOTION
    if n in ("physical", "device", "usb"):
        return PROVIDER_PHYSICAL
    return n
