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
logger = logging.getLogger("jev_test")

async def main():
    package_name = "com.android.insecurebankv2"
    device_serial = "emulator-5554"

    logger.info("Initializing AgenticExplorer for live Jev test...")
    explorer = AgenticExplorer(
        device_serial=device_serial,
        package_name=package_name,
        adb_path="adb"
    )
    
    # We run it directly. Note that usually it's run via FridaSession,
    # but we can try calling start() directly.
    logger.info(f"Planner mode: {os.getenv('SUDARSHAN_PLANNER_MODE')}")
    await explorer.start(duration_seconds=60)
    logger.info("Exploration complete.")

if __name__ == "__main__":
    asyncio.run(main())
