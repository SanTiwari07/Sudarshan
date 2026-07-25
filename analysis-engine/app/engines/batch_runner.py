"""
SUDARSHAN — Batch Runner
=========================
A CLI utility to run Sudarshan on a directory of APKs automatically,
using the MultiStageEngine.
"""

import os
import sys
import asyncio
import logging
from pathlib import Path

from app.engines.multi_stage_engine import MultiStageEngine
from app.engines.frida_sandbox import get_connected_emulators

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("BatchRunner")

async def run_batch(apk_dir: str):
    apk_path = Path(apk_dir)
    if not apk_path.exists() or not apk_path.is_dir():
        logger.error(f"Directory not found: {apk_dir}")
        return

    apks = list(apk_path.glob("*.apk"))
    if not apks:
        logger.info(f"No APKs found in {apk_dir}")
        return
        
    emulators = get_connected_emulators()
    if not emulators:
        logger.error("No Android emulators connected. Start an AVD first.")
        return
        
    device_serial = emulators[0]
    logger.info(f"Found {len(apks)} APKs. Using device: {device_serial}")
    
    success_count = 0
    fail_count = 0
    
    for i, apk in enumerate(apks):
        logger.info(f"\n{'='*50}\n[{i+1}/{len(apks)}] Processing {apk.name}\n{'='*50}")
        try:
            engine = MultiStageEngine(device_serial, str(apk))
            result = await engine.run_all_stages()
            
            if "error" in result:
                logger.error(f"Failed to analyze {apk.name}: {result['error']}")
                fail_count += 1
            else:
                logger.info(f"Successfully analyzed {apk.name}. BFCI: {result.get('bfci')}")
                success_count += 1
        except Exception as e:
            logger.error(f"Exception while analyzing {apk.name}: {e}")
            fail_count += 1
            
    logger.info(f"\nBatch Run Complete. Success: {success_count}, Failed: {fail_count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m app.engines.batch_runner <directory_containing_apks>")
        sys.exit(1)
        
    asyncio.run(run_batch(sys.argv[1]))
