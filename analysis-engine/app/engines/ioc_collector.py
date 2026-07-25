"""
SUDARSHAN — IOC Collector
==========================
Collects Indicators of Compromise (IOCs) dynamically during analysis.
Gathers domains, URLs, IPs, dropped DEX paths, and executes static sweeps 
at the end of the run for databases and shared preferences.
"""

import json
import logging
import subprocess
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Set, Optional

from app.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)


class IOCCollector:
    def __init__(
        self,
        event_bus: Optional[RuntimeEventBus] = None,
        apk_path: Optional[str] = None,
        device_serial: str = "emulator-5554",
        package_name: str = "",
        adb_path: str = "adb"
    ):
        self.apk_path = Path(apk_path) if apk_path else None
        self.device_serial = device_serial
        self.package_name = package_name
        self.adb_path = adb_path

        # Stores unique IOCs by type
        self.iocs: Dict[str, Set[str]] = {
            "domains": set(),
            "urls": set(),
            "ips": set(),
            "dropped_dex": set(),
            "dropped_so": set(),
            "sha256_hashes": set(),
            "yara_matches": set(),
            "accessed_files": set(),
        }

        if self.apk_path and self.apk_path.exists():
            self._add_apk_hash()

        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[IOCCollector] Subscribed to RuntimeEventBus")

    def _add_apk_hash(self):
        try:
            sha256 = hashlib.sha256(self.apk_path.read_bytes()).hexdigest()
            self.iocs["sha256_hashes"].add(sha256)
        except Exception as e:
            logger.error(f"[IOCCollector] Failed to hash APK: {e}")

    def _on_event(self, event: Dict[str, Any]) -> None:
        """Extract IOCs from RuntimeEventBus events."""
        category = event.get("category", "")
        data = event.get("data", {})

        if category == "network":
            url = data.get("url", "")
            if url:
                self.iocs["urls"].add(url)
                # Naive domain extraction (for a robust system, use tldextract)
                try:
                    domain = url.split("://")[-1].split("/")[0].split(":")[0]
                    if domain:
                        self.iocs["domains"].add(domain)
                except:
                    pass

        elif category == "dangerous_apis" and "DexClassLoader" in data.get("hook", ""):
            dex_path = data.get("dex_path", "")
            if dex_path and dex_path != "null":
                self.iocs["dropped_dex"].add(dex_path)

        elif category == "files_accessed":
            path = data.get("path", "")
            if path:
                self.iocs["accessed_files"].add(path)

        elif category == "yara_match":
            rule = data.get("rule_name", "")
            if rule:
                self.iocs["yara_matches"].add(rule)

    def _sweep_app_data(self) -> None:
        """Perform static ADB sweeps at the end of the analysis."""
        if not self.package_name:
            return

        commands = {
            "databases": f"find /data/data/{self.package_name}/databases -name '*.db' 2>/dev/null",
            "shared_prefs": f"find /data/data/{self.package_name}/shared_prefs -name '*.xml' 2>/dev/null",
        }

        for sweep_type, cmd in commands.items():
            try:
                res = subprocess.run(
                    [self.adb_path, "-s", self.device_serial, "shell", cmd],
                    capture_output=True, text=True, timeout=5
                )
                if res.returncode == 0 and res.stdout.strip():
                    files = [f.strip() for f in res.stdout.strip().split("\n") if f.strip()]
                    for f in files:
                        self.iocs["accessed_files"].add(f)
            except Exception as e:
                logger.debug(f"[IOCCollector] Sweep {sweep_type} failed: {e}")

    def flush(self, output_path: Path) -> int:
        """Write deduplicated IOCs to JSON."""
        # Run sweeps before flushing
        self._sweep_app_data()

        # Convert sets to lists
        payload = {k: sorted(list(v)) for k, v in self.iocs.items()}
        total_iocs = sum(len(v) for v in payload.values())
        payload["total_count"] = total_iocs

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=4)
            logger.info(f"[IOCCollector] Flushed {total_iocs} IOCs → {output_path}")
        except Exception as e:
            logger.error(f"[IOCCollector] Failed to write IOCs: {e}")

        return total_iocs
