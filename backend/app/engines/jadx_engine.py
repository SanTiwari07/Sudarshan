"""
SUDARSHAN — JADX Static Analysis Engine
=========================================
Wraps the JADX CLI to decompile DEX bytecode to Java source code, enabling
deeper static code analysis beyond what Androguard's bytecode scanning provides.

JADX integration goals:
  - Decompile .dex bytecode to readable Java source
  - Extract string literals that survive obfuscation (using --show-bad-code)
  - Detect fraud-relevant class names and method signatures in decompiled source
  - Identify dynamic code loading patterns in source context

JADX is NOT required; if not found in PATH the engine degrades gracefully.

Environment variable:
  JADX_PATH   Override path to jadx binary (default: "jadx")

Usage::

    from app.engines.jadx_engine import JadxEngine

    engine = JadxEngine()
    result = engine.analyze(apk_path)
    # result.fraud_class_hits    — list of decompiled class names matching fraud patterns
    # result.suspicious_strings  — string literals from decompiled source
    # result.dynamic_load_hits   — class / method names indicating dynamic loading
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

JADX_PATH: str = os.getenv("JADX_PATH", "jadx")

# ─── Source-level fraud pattern detectors ────────────────────────────────────
# Each pattern is a (label, compiled_regex) pair applied to decompiled .java source.

_FRAUD_PATTERNS = [
    ("ACCESSIBILITY_SERVICE",  re.compile(r"extends\s+AccessibilityService", re.IGNORECASE)),
    ("DEVICE_ADMIN",           re.compile(r"extends\s+DeviceAdminReceiver", re.IGNORECASE)),
    ("SMS_RECEIVER",           re.compile(r"SmsManager\.(sendTextMessage|sendMultipartTextMessage)", re.IGNORECASE)),
    ("OVERLAY_WINDOW",         re.compile(r"WindowManager\.LayoutParams\.TYPE_APPLICATION_OVERLAY", re.IGNORECASE)),
    ("DYNAMIC_CLASS_LOAD",     re.compile(r"(DexClassLoader|InMemoryDexClassLoader)\s*\(", re.IGNORECASE)),
    ("REFLECTION_INVOKE",      re.compile(r"getDeclaredMethod.*invoke|Class\.forName", re.IGNORECASE)),
    ("BANKING_KEYWORD",        re.compile(r"(sbi|hdfc|icici|axis|kotak|phonepe|paytm|bhim|googlepay)", re.IGNORECASE)),
    ("OTP_HARVEST",            re.compile(r"(getMessageBody|SmsMessage\.createFromPdu)", re.IGNORECASE)),
    ("OVERLAY_DRAW",           re.compile(r"WindowManager\.addView|canDrawOverlays", re.IGNORECASE)),
    ("C2_SOCKET",              re.compile(r"new\s+Socket\s*\(|SSLSocketFactory", re.IGNORECASE)),
]

# Limit per-file scan to avoid scanning enormous decompiled projects
_MAX_FILES_TO_SCAN: int = 500
_MAX_FILE_SIZE_BYTES: int = 512 * 1024  # 512 KB


@dataclass
class JadxResult:
    """Output of JADX decompilation and source analysis."""
    available: bool = False
    jadx_version: str = ""
    fraud_class_hits: List[str] = field(default_factory=list)   # e.g. ["ACCESSIBILITY_SERVICE:com.evil.SvcA"]
    suspicious_strings: List[str] = field(default_factory=list)
    dynamic_load_hits: List[str] = field(default_factory=list)
    decompiled_class_count: int = 0
    error: Optional[str] = None


class JadxEngine:
    """
    Wraps the JADX CLI for APK decompilation and source-level fraud pattern scanning.
    """

    def __init__(self, jadx_path: str = JADX_PATH) -> None:
        self.jadx_path = jadx_path
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """Check whether jadx is installed and executable."""
        if self._available is None:
            binary = shutil.which(self.jadx_path)
            self._available = binary is not None
            if not self._available:
                logger.warning(
                    f"[JADX] '{self.jadx_path}' not found in PATH. "
                    "Java source decompilation disabled. Install jadx for enhanced analysis."
                )
        return self._available

    def analyze(self, apk_path: str) -> JadxResult:
        """
        Decompile the APK with JADX and scan for fraud-relevant source patterns.

        Returns JadxResult. If JADX is unavailable or fails, returns a result
        with available=False and no findings.
        """
        if not self.is_available():
            return JadxResult(available=False, error="jadx not found in PATH")

        with tempfile.TemporaryDirectory(prefix="sudarshan_jadx_") as tmp_dir:
            out_dir = Path(tmp_dir) / "src"
            try:
                return self._run_and_analyze(apk_path, out_dir)
            except Exception as e:
                logger.error(f"[JADX] Analysis failed for {apk_path}: {e}")
                return JadxResult(available=False, error=str(e))

    def _run_and_analyze(self, apk_path: str, out_dir: Path) -> JadxResult:
        """Run JADX and scan decompiled Java source for fraud patterns."""
        try:
            proc = subprocess.run(
                [
                    self.jadx_path,
                    "--output-dir", str(out_dir),
                    "--show-bad-code",      # Include classes that failed full decompilation
                    "--no-res",             # Skip resources (APKTool handles those)
                    "--threads-count", "4",
                    apk_path,
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )

            # JADX can exit non-zero even with partial success — check output dir
            if not out_dir.exists() or not any(out_dir.rglob("*.java")):
                error_snippet = proc.stderr[:500] if proc.stderr else "no output produced"
                return JadxResult(available=False, error=f"JADX produced no output: {error_snippet}")

            # Parse version from stderr
            version_match = re.search(r"jadx\s+version\s*([\d.]+)", proc.stderr, re.IGNORECASE)
            version = version_match.group(1) if version_match else "unknown"

        except subprocess.TimeoutExpired:
            return JadxResult(available=False, error="JADX timed out after 180s")
        except FileNotFoundError:
            return JadxResult(available=False, error="JADX binary not found")

        result = JadxResult(available=True, jadx_version=version)
        java_files = list(out_dir.rglob("*.java"))[:_MAX_FILES_TO_SCAN]
        result.decompiled_class_count = len(java_files)

        for java_file in java_files:
            if java_file.stat().st_size > _MAX_FILE_SIZE_BYTES:
                continue
            try:
                source = java_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            class_name = java_file.stem

            for label, pattern in _FRAUD_PATTERNS:
                if pattern.search(source):
                    hit = f"{label}:{class_name}"
                    if label == "DYNAMIC_CLASS_LOAD":
                        result.dynamic_load_hits.append(hit)
                    else:
                        result.fraud_class_hits.append(hit)

            # Extract short suspicious string literals (URLs, tokens, C2 addresses)
            for m in re.finditer(r'"(https?://[^"]{8,200})"', source):
                url = m.group(1)
                if url not in result.suspicious_strings:
                    result.suspicious_strings.append(url)
                    if len(result.suspicious_strings) >= 30:
                        break

        # Deduplicate
        result.fraud_class_hits   = list(dict.fromkeys(result.fraud_class_hits))[:50]
        result.dynamic_load_hits  = list(dict.fromkeys(result.dynamic_load_hits))[:20]
        result.suspicious_strings = list(dict.fromkeys(result.suspicious_strings))[:30]

        logger.info(
            f"[JADX] Analysis complete: {result.decompiled_class_count} classes, "
            f"{len(result.fraud_class_hits)} fraud hits, "
            f"{len(result.dynamic_load_hits)} dynamic load hits"
        )
        return result
