"""
SUDARSHAN — MITRE ATT&CK Mobile Mapper
=======================================
Maps dynamic behaviors (Frida hooks) to MITRE ATT&CK Mobile techniques.
Subscribes to the RuntimeEventBus and produces a mapping file compatible
with the ATT&CK Navigator.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Set, Optional, List

from app.engines.event_bus import RuntimeEventBus

logger = logging.getLogger(__name__)

# Complete hook → ATT&CK Mobile mapping table
HOOK_TO_MITRE = {
    "AccessibilityService.onAccessibilityEvent": {
        "id": "T1417.001",
        "name": "Input Capture: GUI",
        "tactic": "Collection"
    },
    "AccessibilityNodeInfo.performAction": {
        "id": "T1417.002",
        "name": "Input Injection",
        "tactic": "Impact"
    },
    "SmsManager.sendTextMessage": {
        "id": "T1582",
        "name": "SMS Control",
        "tactic": "Impact"
    },
    "ContentResolver.query": {
        "id": "T1636.004",
        "name": "Protected Data: SMS",
        "tactic": "Collection" # Assuming SMS query
    },
    "WindowManager.addView": {
        "id": "T1416",
        "name": "Input Injection",  # Overlay abuse is often classified under Input Injection/Phishing
        "tactic": "Impact" 
    },
    "DexClassLoader.<init>": {
        "id": "T1407",
        "name": "Download New Code at Runtime",
        "tactic": "Defense Evasion"
    },
    "DevicePolicyManager.isAdminActive": {
        "id": "T1626.001",
        "name": "Device Admin",
        "tactic": "Persistence"
    },
    "DevicePolicyManager.lockNow": {
        "id": "T1626.001", # Actually ransomware, but categorized under device admin abuse
        "name": "Device Admin",
        "tactic": "Impact"
    },
    "URL.openConnection": {
        "id": "T1437.001",
        "name": "Web Protocols",
        "tactic": "Command and Control"
    },
    "OkHttp.RealCall.execute": {
        "id": "T1437.001",
        "name": "Web Protocols",
        "tactic": "Command and Control"
    },
    "KeyStore.getInstance": {
        "id": "T1634",
        "name": "Credentials from Password Store",
        "tactic": "Credential Access"
    },
    "SystemProperties.get": {
        "id": "T1497.001",
        "name": "Virtualization/Sandbox Evasion: System Checks",
        "tactic": "Defense Evasion"
    },
    "Debug.isDebuggerConnected": {
        "id": "T1497.001",
        "name": "Virtualization/Sandbox Evasion: System Checks",
        "tactic": "Defense Evasion"
    },
    "Build.MODEL.read": {
        "id": "T1497.001",
        "name": "Virtualization/Sandbox Evasion: System Checks",
        "tactic": "Defense Evasion"
    },
    "PackageManager.getPackageInfo": {
        "id": "T1497.001",
        "name": "Virtualization/Sandbox Evasion: System Checks",
        "tactic": "Defense Evasion"
    },
}

class MitreMapper:
    def __init__(self, event_bus: Optional[RuntimeEventBus] = None):
        # Store matched techniques. Key is technique ID to prevent duplicates.
        self.matched_techniques: Dict[str, Dict[str, Any]] = {}

        if event_bus:
            event_bus.subscribe(self._on_event)
            logger.debug("[MitreMapper] Subscribed to RuntimeEventBus")

    def _on_event(self, event: Dict[str, Any]) -> None:
        """Map Frida events to MITRE ATT&CK techniques."""
        data = event.get("data", {})
        hook = data.get("hook", "")
        
        # Special case handling
        if hook == "ContentResolver.query":
            uri = data.get("args", [""])[0] if data.get("args") else ""
            if "sms" not in uri and "mms" not in uri:
                return # Only mapping SMS queries for now

        if hook in HOOK_TO_MITRE:
            tech = HOOK_TO_MITRE[hook]
            tech_id = tech["id"]
            if tech_id not in self.matched_techniques:
                self.matched_techniques[tech_id] = {
                    "techniqueID": tech_id,
                    "techniqueName": tech["name"],
                    "tactic": tech["tactic"],
                    "score": 100,  # Arbitrary score to colorize the Navigator layer
                    "comment": f"Triggered by {hook}",
                    "enabled": True,
                    "metadata": []
                }
            
            # Append context to comment if we see it multiple times from different hooks
            if hook not in self.matched_techniques[tech_id]["comment"]:
                self.matched_techniques[tech_id]["comment"] += f", {hook}"

    def flush(self, output_path: Path) -> int:
        """Write MITRE matches to standard JSON and an ATT&CK Navigator layer."""
        if not self.matched_techniques:
            return 0

        techniques = list(self.matched_techniques.values())

        # Standard output
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump({"techniques": techniques}, f, indent=4)
        except Exception as e:
            logger.error(f"[MitreMapper] Failed to write mitre.json: {e}")

        # ATT&CK Navigator layer output
        layer_path = output_path.parent / "attack_navigator_layer.json"
        layer = {
            "name": "Sudarshan Dynamic Analysis",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5"
            },
            "domain": "mobile-attack",
            "description": "Techniques observed during dynamic analysis.",
            "filters": {
                "platforms": ["Android"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": False,
                "showName": True,
                "showAggregateScores": False,
                "countUnscored": False
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": [
                    "#ff6666ff",
                    "#ffe766ff",
                    "#8ec843ff"
                ],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectSubtechniquesWithParent": False,
            "selectModifiers": {
                "platforms": ["Android"]
            }
        }

        try:
            with open(layer_path, "w", encoding="utf-8") as f:
                json.dump(layer, f, indent=4)
            logger.info(f"[MitreMapper] Flushed {len(techniques)} techniques → {output_path} and {layer_path}")
        except Exception as e:
            logger.error(f"[MitreMapper] Failed to write attack_navigator_layer.json: {e}")

        return len(techniques)
