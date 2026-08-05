#!/usr/bin/env python3
"""
Sudarshan Dynamic Validation Framework — entry point.

  python validate_dynamic_pipeline.py [--fetch] [--stress 10,20] [--recovery]

Runs every corpus APK (continues on failure), writes reports under
tests/apks/validation_runs/<timestamp>/.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "shared"))
sys.path.insert(0, str(ROOT / "backend"))

if not os.environ.get("JWT_SECRET_KEY"):
    os.environ["JWT_SECRET_KEY"] = "sudarshan_validation_jwt_key"

from sudarshan_core.engines.frida_sandbox import get_connected_emulators
from sudarshan_core.validation.corpus import fetch_all, load_corpus
from sudarshan_core.validation.engineering_report import build_engineering_report
from sudarshan_core.validation.recovery import run_recovery_suite, save_recovery_report
from sudarshan_core.validation.runner import validate_all
from sudarshan_core.validation.stress import run_stress, save_stress_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("validate_dynamic_pipeline")


def _parse_stress(spec: str) -> list[int]:
    if not spec:
        return []
    return [int(x.strip()) for x in spec.split(",") if x.strip()]


async def _main_async(args: argparse.Namespace) -> int:
    if args.fetch:
        fetch_all()

    entries = load_corpus()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "tests" / "apks" / "validation_runs" / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "verify_runtime_pipeline",
        ROOT / "scripts" / "verify_runtime_pipeline.py",
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    logger.info("Running sandbox preflight (verify_runtime_pipeline)...")
    preflight_ok = mod.run_pipeline_verification()
    (out_dir / "preflight.txt").write_text(
        f"preflight_ok={preflight_ok}\n", encoding="utf-8"
    )
    if not preflight_ok and not args.force:
        logger.error("Preflight failed — fix sandbox or use --force to run anyway")
        return 2

    results = await validate_all(entries, out_dir / "apk_runs")

    stress_payloads = []
    stress_counts = _parse_stress(args.stress)
    stress_apk = next(
        (e for e in entries if e.apk_path.is_file() and not e.optional),
        next((e for e in entries if e.apk_path.is_file()), None),
    )
    for n in stress_counts:
        if not stress_apk:
            logger.warning("No APK for stress test — skip")
            break
        logger.info("Stress test: %d iterations on %s", n, stress_apk.id)
        sr = await run_stress(stress_apk, n)
        sp = out_dir / f"stress_{n}.json"
        save_stress_report(sr, sp)
        stress_payloads.append(sr.to_dict())

    recovery_dict = None
    if args.recovery and stress_apk:
        serials = get_connected_emulators()
        if serials:
            logger.info("Recovery suite on %s", serials[0])
            rr = await run_recovery_suite(stress_apk, serials[0])
            save_recovery_report(rr, out_dir / "recovery.json")
            recovery_dict = rr.to_dict()

    build_engineering_report(results, stress_payloads, recovery_dict, out_dir)

    executed = [r for r in results if not r.skipped]
    passed = sum(1 for r in executed if r.status == "PASS")
    logger.info(
        "Validation complete: %d/%d passed (skipped %d). Report: %s",
        passed,
        len(executed),
        sum(1 for r in results if r.skipped),
        out_dir,
    )
    return 0 if passed == len(executed) and executed else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Sudarshan dynamic validation framework")
    parser.add_argument("--fetch", action="store_true", help="Download APKs with fetch_url")
    parser.add_argument("--stress", default="", help="Comma-separated iteration counts e.g. 10,20")
    parser.add_argument("--recovery", action="store_true", help="Run recovery scenario suite")
    parser.add_argument("--force", action="store_true", help="Run even if preflight fails")
    args = parser.parse_args()
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
