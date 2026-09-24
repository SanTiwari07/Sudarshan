import asyncio
import os
import sys
import logging
from pathlib import Path

# Add shared/ and backend/ to sys.path
_ROOT = Path(__file__).resolve().parent.parent
_SHARED = _ROOT / "shared"
_BACKEND = _ROOT / "backend"
for _p in (_SHARED, _BACKEND):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from sudarshan_core.engines.agentic_explorer import AgenticExplorer
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("laya_test")

async def main():
    package_name = "com.android.insecurebankv2"
    device_serial = "emulator-5554"

    # Explicitly configure Laya in local mode for the test
    os.environ["SUDARSHAN_PLANNER_MODE"] = "laya_hybrid"
    os.environ["LAYA_MODE"] = "in_process"
    os.environ["SUDARSHAN_LAYA_DEVICE"] = "cpu"

    logger.info("Initializing AgenticExplorer for live Laya test...")
    explorer = AgenticExplorer(
        device_serial=device_serial,
        package_name=package_name,
        adb_path="adb"
    )
    
    logger.info(f"Planner mode: {os.getenv('SUDARSHAN_PLANNER_MODE')}")
    # Give it a 90 second budget to do deep exploration
    await explorer.start(duration_seconds=90)
    logger.info("Exploration complete.")

if __name__ == "__main__":
    asyncio.run(main())
