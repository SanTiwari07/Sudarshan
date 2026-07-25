"""
SUDARSHAN — Multi-Stage Analysis Engine
========================================
Orchestrates multiple analysis runs for a single APK across different
simulated device states (e.g. Fresh Install -> Accessibility Enabled -> Rebooted).
Aggregates the highest BFCI score across all stages.
"""

import json
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, List, Optional

from app.engines.frida_sandbox import run_frida_analysis, get_connected_emulators
from app.engines.device_state_simulator import DeviceStateSimulator

logger = logging.getLogger(__name__)

class MultiStageEngine:
    def __init__(self, apk_path: str, device_serial: Optional[str] = None, package_name: Optional[str] = None):
        if not device_serial:
            emulators = get_connected_emulators()
            if emulators:
                device_serial = emulators[0]
            else:
                logger.warning("[MultiStage] No emulators connected. Multi-stage will likely fail.")
        self.device_serial = device_serial
        self.apk_path = apk_path
        self.package_name = package_name
        self.stages = [
            {"name": "fresh_install", "profile": None},
            {"name": "sim_active", "profile": "sim_present"},
            {"name": "banking_apps", "profile": "banking_apps"},
            {"name": "rebooted", "profile": "reboot"}
        ]
        self.simulator = DeviceStateSimulator(device_serial)

    async def run_all_stages(self) -> Dict[str, Any]:
        logger.info(f"[MultiStage] Starting multi-stage analysis for {self.apk_path}")
        
        results = []
        highest_bfci = 0.0
        primary_result = None
        
        # Ensure clean state before starting
        self.simulator.reset()
        
        for stage in self.stages:
            logger.info(f"\n[MultiStage] --- Executing Stage: {stage['name']} ---")
            
            # Device Health Check
            emulators = get_connected_emulators()
            if self.device_serial and self.device_serial not in emulators:
                logger.error(f"[MultiStage] Device {self.device_serial} disconnected! Aborting remaining stages.")
                break
            
            if stage["profile"]:
                self.simulator.apply_profile(stage["profile"])
                await asyncio.sleep(2)
                
            # Run the actual sandbox analysis for this stage
            try:
                # We can't easily pass the stage name to the inner `run_frida_analysis` 
                # without modifying its signature, but we can tag the result afterward.
                # In a real implementation we would modify run_frida_analysis to take `stage_name`.
                result = await run_frida_analysis(self.apk_path, package_name=self.package_name)
                result["stage"] = stage["name"]
                result["stage_status"] = "success"
                
                results.append(result)
                
                bfci = result.get("bfci", 0.0)
                logger.info(f"[MultiStage] Stage {stage['name']} complete. BFCI: {bfci}")
                
                if bfci > highest_bfci or not primary_result:
                    highest_bfci = bfci
                    primary_result = dict(result) # copy
                    
            except Exception as e:
                logger.error(f"[MultiStage] Stage {stage['name']} failed: {e}")
                results.append({"stage": stage["name"], "stage_status": "failed", "error": str(e), "bfci": 0.0})
                
        # Clean up
        self.simulator.reset()
        
        if not primary_result:
            return {"error": "All stages failed."}
            
        # The primary result represents the worst-case behavior
        primary_result["multi_stage_summary"] = {
            "total_stages": len(self.stages),
            "stages_run": [r.get("stage") for r in results],
            "highest_bfci_stage": primary_result.get("stage"),
            "stage_scores": {r.get("stage"): r.get("bfci", 0) for r in results},
            "stage_statuses": {r.get("stage"): r.get("stage_status", "unknown") for r in results}
        }
        
        logger.info(f"[MultiStage] Multi-stage complete. Highest BFCI: {highest_bfci} (Stage: {primary_result.get('stage')})")
        return primary_result

# Example entry point for CLI usage
async def main(apk_path: str, device_serial: Optional[str] = None):
    engine = MultiStageEngine(apk_path, device_serial)
    result = await engine.run_all_stages()
    print(json.dumps(result["multi_stage_summary"], indent=4))

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2:
        asyncio.run(main(sys.argv[1], sys.argv[2]))
    else:
        print("Usage: python multi_stage_engine.py <apk_path> <device_serial>")
