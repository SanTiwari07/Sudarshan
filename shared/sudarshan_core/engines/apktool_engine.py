"""
SUDARSHAN — APKTool Static Analysis Engine
==========================================
Wraps the APKTool CLI to decompile an APK's resources and extract a
decoded AndroidManifest.xml when MobSF is unavailable.

APKTool integration goals:
  - Extract a human-readable (decoded) AndroidManifest.xml for component analysis
  - Enumerate resources for embedded URLs, encoded strings, and suspicious assets
  - Detect obfuscated resource names (short single-character resource identifiers)

APKTool is NOT required; if not found in PATH the engine degrades gracefully
and logs a warning. All static analysis continues through Androguard.

Environment variable:
  APKTOOL_PATH   Override path to apktool binary (default: "apktool")

Usage::

    from sudarshan_core.engines.apktool_engine import ApktoolEngine

    engine = ApktoolEngine()
    result = engine.analyze(apk_path)
    # result.decoded_manifest_xml  — raw XML string (or empty if apktool unavailable)
    # result.suspicious_resources  — list of suspicious resource file paths
    # result.resource_strings      — list of strings extracted from resources
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

APKTOOL_PATH: str = os.getenv("APKTOOL_PATH", "apktool")

# Patterns that indicate suspicious content in resource strings
_SUSPICIOUS_RESOURCE_PATTERNS = [
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE),
    re.compile(r"https?://[a-z0-9\-]+\.(top|xyz|ru|tk|pw|cc)\b", re.IGNORECASE),
    re.compile(r"(accessibilityservice|android\.permission\.SEND_SMS)", re.IGNORECASE),
    re.compile(r"(TYPE_APPLICATION_OVERLAY|SYSTEM_ALERT_WINDOW)", re.IGNORECASE),
]


@dataclass
class ApktoolResult:
    """Output of APKTool decompilation."""
    available: bool = False
    apktool_version: str = ""
    decoded_manifest_xml: str = ""
    suspicious_resources: List[str] = field(default_factory=list)
    resource_strings: List[str] = field(default_factory=list)
    obfuscated_resource_count: int = 0
    error: Optional[str] = None


class ApktoolEngine:
    """
    Wraps the APKTool CLI for static resource decompilation.

    Decompilation runs in a temporary directory that is always cleaned up,
    even on failure.
    """

    def __init__(self, apktool_path: str = APKTOOL_PATH) -> None:
        self.apktool_path = apktool_path
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check whether apktool is installed and executable."""
        if self._available is None:
            binary = shutil.which(self.apktool_path)
            if not binary and self.apktool_path in ("apktool", APKTOOL_PATH):
                # Check workspace local tools directory
                workspace_root = Path(__file__).resolve().parents[3]
                local_bat = workspace_root / "tools" / "apktool" / "apktool.bat"
                if local_bat.exists():
                    binary = str(local_bat)
                    self.apktool_path = binary

            self._available = binary is not None
            if not self._available:
                logger.warning(
                    f"[APKTool] '{self.apktool_path}' not found in PATH or local tools dir. "
                    "Resource decompilation disabled. Install apktool for enhanced analysis."
                )
        return self._available

    def analyze(self, apk_path: str) -> ApktoolResult:
        """
        Decompile the APK using apktool and extract static intelligence.

        Returns ApktoolResult. If apktool is unavailable or fails, returns
        a result with available=False and no findings.
        """
        if not self.is_available():
            return ApktoolResult(available=False, error="apktool not found in PATH")

        with tempfile.TemporaryDirectory(prefix="sudarshan_apktool_") as tmp_dir:
            out_dir = Path(tmp_dir) / "decompiled"
            try:
                return self._run_and_analyze(apk_path, out_dir)
            except Exception as e:
                logger.error(f"[APKTool] Analysis failed for {apk_path}: {e}")
                return ApktoolResult(available=False, error=str(e))

    def _run_and_analyze(self, apk_path: str, out_dir: Path) -> ApktoolResult:
        """Run apktool and extract intelligence from decompiled output."""
        try:
            proc = subprocess.run(
                [self.apktool_path, "d", "-f", "-o", str(out_dir), apk_path],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode != 0:
                logger.warning(f"[APKTool] Non-zero exit: {proc.stderr[:500]}")
                return ApktoolResult(available=False, error=f"apktool exited {proc.returncode}")

            # ── Extract version from stderr
            version_match = re.search(r"apktool\s+v?([\d.]+)", proc.stderr, re.IGNORECASE)
            version = version_match.group(1) if version_match else "unknown"

        except subprocess.TimeoutExpired:
            return ApktoolResult(available=False, error="apktool timed out after 120s")
        except FileNotFoundError:
            return ApktoolResult(available=False, error="apktool binary not found")

        result = ApktoolResult(available=True, apktool_version=version)

        # ── Read decoded AndroidManifest.xml
        manifest_path = out_dir / "AndroidManifest.xml"
        if manifest_path.exists():
            try:
                result.decoded_manifest_xml = manifest_path.read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                logger.warning(f"[APKTool] Could not read AndroidManifest.xml: {e}")

        # ── Scan resources directory
        res_dir = out_dir / "res"
        if res_dir.exists():
            for fpath in res_dir.rglob("*"):
                if not fpath.is_file():
                    continue

                # Obfuscation signal: single-char resource names
                if len(fpath.stem) == 1 and fpath.suffix in (".xml", ".png", ".jpg"):
                    result.obfuscated_resource_count += 1

                # Only scan text-like files for suspicious strings
                if fpath.suffix in (".xml", ".txt", ".json", ".properties"):
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="replace")
                        for pattern in _SUSPICIOUS_RESOURCE_PATTERNS:
                            matches = pattern.findall(content)
                            if matches:
                                result.suspicious_resources.append(str(fpath.relative_to(out_dir)))
                                result.resource_strings.extend(matches[:5])
                                break
                    except Exception:
                        pass

        # Deduplicate
        result.resource_strings = list(dict.fromkeys(result.resource_strings))[:50]
        result.suspicious_resources = list(dict.fromkeys(result.suspicious_resources))[:20]

        logger.info(
            f"[APKTool] Analysis complete: {len(result.suspicious_resources)} suspicious resources, "
            f"{result.obfuscated_resource_count} obfuscated resource names, "
            f"manifest_len={len(result.decoded_manifest_xml)}"
        )
        return result
