"""
Red-team regression: ToolExecutor must not bypass SandboxProvider ADB policy.
"""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from sudarshan_core.engines.agentic.tool_executor import ToolExecutor


def test_tool_executor_uses_sandbox_provider_not_raw_subprocess():
    executor = ToolExecutor(
        device_serial="192.168.56.101:5555",
        adb_path="/should/not/be/used",
        package_name="com.example.app",
    )
    mock_provider = MagicMock()
    mock_provider.adb.return_value = (True, "ok")

    async def _run():
        with patch(
            "sudarshan_core.engines.agentic.tool_executor.get_sandbox_provider",
            return_value=mock_provider,
        ):
            return await executor._adb("shell", "echo", "test")

    ok, out = asyncio.run(_run())
    assert ok and out == "ok"
    mock_provider.adb.assert_called_once()
    call_args = mock_provider.adb.call_args[0]
    assert call_args[0] == "-s"
    assert call_args[1] == "192.168.56.101:5555"
    assert call_args[2] == "shell"
