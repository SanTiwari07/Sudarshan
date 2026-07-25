"""
SUDARSHAN — YARA Scanner
=========================
Runtime YARA matching against in-memory strings and pulled artifacts.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

from app.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)

class YARAScanner:
    def __init__(self, rules_dir: Path, event_bus: Optional[RuntimeEventBus] = None):
        self.rules_dir = Path(rules_dir)
        self.event_bus = event_bus
        self.matches: List[Dict[str, Any]] = []
        self.yara_available = False
        self.rules = None
        
        try:
            import yara
            self.yara_available = True
        except ImportError:
            logger.warning("[YARAScanner] yara-python not installed. YARA scanning disabled.")
            return

        # Compile all .yar files in rules_dir
        if self.rules_dir.exists():
            filepaths = {}
            for f in self.rules_dir.glob("*.yar"):
                filepaths[f.stem] = str(f)
            
            if filepaths:
                try:
                    self.rules = yara.compile(filepaths=filepaths)
                    logger.info(f"[YARAScanner] Compiled {len(filepaths)} YARA rulesets.")
                except Exception as e:
                    logger.error(f"[YARAScanner] Failed to compile YARA rules: {e}")

    def _publish_match(self, rule_name: str, target: str, strings_matched: List[str]):
        match = {
            "rule_name": rule_name,
            "target": target,
            "strings": strings_matched
        }
        self.matches.append(match)
        if self.event_bus:
            self.event_bus.publish({
                "type": "event",
                "category": "yara_match",
                "severity": "HIGH",
                "data": match
            })
            
    def scan_file(self, file_path: Path) -> bool:
        """Scan a local file (e.g. downloaded APK, dumped DEX, pulled DB)."""
        if not self.yara_available or not self.rules or not Path(file_path).exists():
            return False
            
        try:
            matches = self.rules.match(str(file_path))
            for match in matches:
                strings = list(set([s[2].decode(errors="ignore") for s in match.strings]))
                self._publish_match(match.rule, str(file_path.name), strings)
                logger.info(f"[YARAScanner] YARA Match: {match.rule} in {file_path.name}")
            return True
        except Exception as e:
            logger.error(f"[YARAScanner] File scan failed: {e}")
            return False

    def scan_strings(self, strings: List[str], target_name: str = "memory_strings") -> bool:
        """Scan an arbitrary list of strings (e.g. decrypted URLs from Frida)."""
        if not self.yara_available or not self.rules or not strings:
            return False
            
        try:
            # Join strings with newlines and scan as a buffer
            buffer = "\n".join(strings).encode("utf-8")
            matches = self.rules.match(data=buffer)
            for match in matches:
                matched_strs = list(set([s[2].decode(errors="ignore") for s in match.strings]))
                self._publish_match(match.rule, target_name, matched_strs)
                logger.info(f"[YARAScanner] YARA Match: {match.rule} in {target_name}")
            return True
        except Exception as e:
            logger.error(f"[YARAScanner] Strings scan failed: {e}")
            return False

    def flush(self, output_path: Path) -> int:
        """Write matches to JSON."""
        if not self.matches:
            return 0
            
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.matches, f, indent=4)
            logger.info(f"[YARAScanner] Flushed {len(self.matches)} matches → {output_path}")
        except Exception as e:
            logger.error(f"[YARAScanner] Failed to write yara_results.json: {e}")
            
        return len(self.matches)
