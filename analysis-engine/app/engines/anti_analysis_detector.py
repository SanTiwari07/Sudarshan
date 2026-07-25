"""
SUDARSHAN — Anti-Analysis Detector
===================================
Listens for 'anti_analysis' events from the RuntimeEventBus. These events are
emitted by Frida hooks when malware tries to probe for an emulator, debugger,
or security tool.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)

class AntiAnalysisDetector:
    def __init__(self, event_bus: Optional[RuntimeEventBus] = None):
        self.detections: List[Dict[str, Any]] = []
        
        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[AntiAnalysisDetector] Subscribed to RuntimeEventBus")

    def _on_event(self, event: Dict[str, Any]) -> None:
        if event.get("category") == "anti_analysis":
            data = event.get("data", {})
            detection = {
                "timestamp": event.get("timestamp", int(datetime.now(tz=timezone.utc).timestamp() * 1000)),
                "technique": data.get("technique", "unknown"),
                "hook": data.get("hook", ""),
                "description": data.get("description", ""),
                "severity": data.get("severity", "HIGH"),
                "details": {k: v for k, v in data.items() if k not in ["technique", "hook", "description", "severity"]}
            }
            self.detections.append(detection)
            logger.warning(f"[AntiAnalysis] Detected evasion attempt: {detection['technique']} via {detection['hook']}")

    def flush(self, output_path: Path) -> int:
        """Write detections to JSON."""
        if not self.detections:
            return 0
            
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.detections, f, indent=4)
            logger.info(f"[AntiAnalysisDetector] Flushed {len(self.detections)} detections → {output_path}")
        except Exception as e:
            logger.error(f"[AntiAnalysisDetector] Failed to write anti_analysis.json: {e}")
            
        return len(self.detections)
