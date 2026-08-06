"""Regression tests for formal-verification blocker fixes."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from sudarshan_core.engines.agentic.perception import PerceptionPipeline
from sudarshan_core.engines.ioc_collector import IOCCollector
from sudarshan_core.security.sandbox_containment import (
    ContainmentViolation,
    validate_backend_production_config,
)


def test_backend_production_config_requires_internal_token(monkeypatch):
    monkeypatch.setenv("SUDARSHAN_ENV", "production")
    monkeypatch.delenv("ANALYSIS_ENGINE_INTERNAL_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="ANALYSIS_ENGINE_INTERNAL_TOKEN"):
        validate_backend_production_config()


def test_backend_production_config_allows_token(monkeypatch):
    monkeypatch.setenv("SUDARSHAN_ENV", "production")
    monkeypatch.setenv("ANALYSIS_ENGINE_INTERNAL_TOKEN", "secret")
    validate_backend_production_config()


def test_perception_pipeline_uses_sandbox_provider():
    pipeline = PerceptionPipeline("192.168.56.101:5555", "com.example.app")
    mock_provider = MagicMock()
    mock_provider.adb.return_value = (True, '<?xml version="1.0"?><hierarchy/>')

    async def _run():
        with patch(
            "sudarshan_core.engines.agentic.perception.get_sandbox_provider",
            return_value=mock_provider,
        ):
            return await pipeline._dump_ui_xml()

    result = asyncio.run(_run())
    assert result is not None
    assert mock_provider.adb.call_count >= 2
    first_call = mock_provider.adb.call_args_list[0][0]
    assert first_call[0] == "-s"
    assert first_call[1] == "192.168.56.101:5555"


def test_ioc_collector_sweep_uses_sandbox_provider():
    collector = IOCCollector(
        device_serial="192.168.56.101:5555",
        package_name="com.evil.app",
    )
    mock_provider = MagicMock()
    mock_provider.adb.return_value = (True, "/data/data/com.evil.app/databases/x.db\n")

    with patch(
        "sudarshan_core.engines.ioc_collector.get_sandbox_provider",
        return_value=mock_provider,
    ):
        collector._sweep_app_data()

    assert mock_provider.adb.called
    args = mock_provider.adb.call_args[0]
    assert args[0] == "-s"
    assert args[1] == "192.168.56.101:5555"
    assert args[2] == "shell"


def test_adb_bootstrap_rejects_host_docker_internal_connect(monkeypatch):
    import importlib.util
    from pathlib import Path

    module_path = (
        Path(__file__).resolve().parents[2]
        / "analysis-engine"
        / "app"
        / "adb_bootstrap.py"
    )
    spec = importlib.util.spec_from_file_location("adb_bootstrap", module_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    bootstrap_adb_connect = mod.bootstrap_adb_connect

    monkeypatch.setenv("ADB_HOST", "host.docker.internal")
    monkeypatch.setenv("ADB_PORT", "5555")
    monkeypatch.setenv("SANDBOX_PROVIDER", "genymotion")
    with pytest.raises(ContainmentViolation):
        bootstrap_adb_connect(max_attempts=1, retry_sleep_seconds=0)
