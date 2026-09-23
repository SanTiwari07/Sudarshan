import asyncio
import os
import sys
import logging
from pathlib import Path

# Add shared/ to sys.path
_ROOT = Path(__file__).resolve().parent.parent
_SHARED = _ROOT / "shared"
_BACKEND = _ROOT / "backend"
sys.path.insert(0, str(_SHARED))
sys.path.insert(0, str(_BACKEND))

os.environ["SUDARSHAN_PLANNER_MODE"] = "hybrid"
os.environ["SUDARSHAN_JEV_PROVIDER"] = "mock"
if "ADB_SERVER_SOCKET" in os.environ:
    del os.environ["ADB_SERVER_SOCKET"]
os.environ["ADB_SERVER_SOCKET"] = "tcp:127.0.0.1:5037"

from sudarshan_core.engines.agentic_explorer import AgenticExplorer
import adbutils

adbutils.adb.server_version = lambda: 41
adbutils.adb.ensure_server = lambda: None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phase6_e2e")

async def main():
    logger.info("Initializing AgenticExplorer for Phase 6 E2E Test...")
    explorer = AgenticExplorer(
        device_serial="emulator-5554",
        package_name="com.android.insecurebankv2",
        adb_path="adb"
    )
    
    try:
        # Run exploration with a 60 second budget
        await explorer.start(duration_seconds=60)
    except Exception as e:
        logger.error(f"Explorer stopped: {e}")

    traces = explorer.dispatcher.traces
    print(f"\nCompleted E2E Investigation")
    print(f"Total actions taken: {len(traces)}")
    for i, tr in enumerate(traces):
        d = tr.to_dict()
        act = d.get('action', {})
        print(f"  Cycle {i+1}: Tool: {act.get('tool')} | Text: {act.get('text')} | Executed: {d.get('action_execution')} | Verified: {d.get('action_verification')}")

if __name__ == "__main__":
    asyncio.run(main())
