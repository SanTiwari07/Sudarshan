"""ScreenshotManager respects SUDARSHAN_DISABLE_SCREENSHOTS."""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from sudarshan_core.engines.screenshot_manager import ScreenshotManager


@pytest.fixture
def manager(tmp_path):
    bus = MagicMock()
    return ScreenshotManager(
        device_serial="emulator-5554",
        output_dir=tmp_path,
        event_bus=bus,
        package_name="com.test",
    )


def test_capture_disabled_by_env(manager, monkeypatch):
    monkeypatch.setenv("SUDARSHAN_DISABLE_SCREENSHOTS", "true")
    with patch("sudarshan_core.engines.screenshot_manager.get_sandbox_provider") as mock_prov:
        ref = manager.capture("test", reason="LIFECYCLE", force=True)
    assert ref is None
    mock_prov.assert_not_called()
