import asyncio
import os
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

try:
    from validate_dynamic_pipeline import _main_async
    import argparse
except ImportError:
    pass

def test_validate_dynamic_pipeline_regression():
    """
    Automated regression test case for the full dynamic pipeline.
    Runs validate_dynamic_pipeline.py programmatically.
    Requires a connected Android Sandbox (emulator-5554).
    """
    from sudarshan_core.engines.frida_sandbox import get_connected_emulators
    import argparse
    emulators = get_connected_emulators()
    if not emulators:
        pytest.skip("No emulator connected - skipping dynamic pipeline regression test")

    try:
        from validate_dynamic_pipeline import _main_async
    except ImportError:
        pytest.skip("validate_dynamic_pipeline.py not found - skipping test")

    args = argparse.Namespace(fetch=False, stress="", recovery=False, force=True)
    
    # We run it and assert it returns 0 (which means all executed runs passed).
    result_code = asyncio.run(_main_async(args))
    assert result_code == 0, f"Dynamic pipeline validation failed with code {result_code}"
