import asyncio
import os
import sys
import json
import logging
from pathlib import Path

# Force the environment before any imports happen
os.environ["SUDARSHAN_PLANNER_MODE"] = "jev"
os.environ["SUDARSHAN_JEV_PROVIDER"] = "mock"

# Add shared/ and backend/ to sys.path
_ROOT = Path(__file__).resolve().parent.parent
_SHARED = _ROOT / "shared"
_BACKEND = _ROOT / "backend"
for _p in (_SHARED, _BACKEND):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from sudarshan_core.engines.agentic_explorer import AgenticExplorer

import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("jev_mock_test")

import adbutils
adbutils.adb.server_version = lambda: 41
adbutils.adb.ensure_server = lambda: None

from sudarshan_core.engines.agentic.jev_planner import JevPlanner
original_invoke = JevPlanner._invoke_mock
async def patched_invoke(self, obs, goals, candidates):
    cands = [c for c in candidates if "scroll" not in c.action_id and "scroll" not in getattr(c, "action_type", "")]
    for c in cands:
        if getattr(c, "action_type", "") == "click":
            c.action_type = "tap"
    return await original_invoke(self, obs, goals, cands)
JevPlanner._invoke_mock = patched_invoke

async def main():
    package_name = "com.android.insecurebankv2"
    device_serial = "emulator-5554"

    logger.info("Initializing AgenticExplorer for live JEV MOCK test...")
    explorer = AgenticExplorer(
        device_serial=device_serial,
        package_name=package_name,
        adb_path="adb"
    )
    
    logger.info(f"Planner mode: {os.getenv('SUDARSHAN_PLANNER_MODE')} | Provider: {os.getenv('SUDARSHAN_JEV_PROVIDER')}")
    
    # Restrict to ~200 seconds to allow for ADB fallback timeouts and still get 3-5 cycles
    await explorer.start(duration_seconds=200)
    logger.info("Exploration complete. Extracting metrics...")

    traces = explorer.dispatcher.traces
    print("\n" + "="*80)
    print("METRICS REPORT (JEV PROVIDER = MOCK)")
    print("="*80)
    
    print(f"Total Cycles Completed: {len(traces)}")
    print(f"{'Cycle':<5} | {'Candidates':<10} | {'Selected':<15} | {'Decision':<9} | {'Execution':<10} | {'Verification':<12} | {'Result':<10}")
    print("-" * 80)
    
    successful = 0
    failed = 0
    fallback = 0
    verification_failures = 0

    for i, t in enumerate(traces):
        d = t.to_dict()
        
        cands = len(d.get("action", {}).get("candidates", [])) if "candidates" in d.get("action", {}) else "?"
        sel = d.get("action", {}).get("tool", "unknown")
        
        # We might not have raw execution latencies in ActionTrace easily accessible depending on the implementation
        # But we can try to guess from the logs or trace dictionary. 
        # For now, let's just extract what we can safely.
        
        dec_lat = f"{d.get('planner_latency_ms', 0) / 1000.0:.2f}s" if 'planner_latency_ms' in d else "N/A"
        exec_lat = f"{d.get('execution_latency_ms', 0) / 1000.0:.2f}s" if 'execution_latency_ms' in d else "N/A"
        ver_lat = f"{d.get('verification_latency_ms', 0) / 1000.0:.2f}s" if 'verification_latency_ms' in d else "N/A"
        res = d.get("action_verification", "UNKNOWN")
        
        if res == "PASS":
            successful += 1
        else:
            failed += 1
            verification_failures += 1
            
        if d.get("action", {}).get("_selected_by") == "gemini":
            fallback += 1
            
        print(f"{i+1:<5} | {cands:<10} | {sel:<15} | {dec_lat:<9} | {exec_lat:<10} | {ver_lat:<12} | {res:<10}")

    print("\nSUMMARY:")
    print(f"- Successful actions: {successful}")
    print(f"- Failed actions: {failed}")
    print(f"- Verification failures: {verification_failures}")
    print(f"- Fallbacks to Gemini: {fallback}")
    print("="*80)

if __name__ == "__main__":
    asyncio.run(main())
