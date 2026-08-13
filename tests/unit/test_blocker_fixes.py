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


def test_adb_bootstrap_rejects_host_docker_internal_connect(monkeypatch, capsys):
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
    
    # Run the bootstrap, it shouldn't raise, but it should print the rejection
    res = bootstrap_adb_connect(max_attempts=1, retry_sleep_seconds=0)
    assert res == 0
    captured = capsys.readouterr().out
    assert "Genymotion requires a valid VM IP" in captured
    assert "target=auto" in captured
    assert "tcp_connect=SKIPPED" in captured

def test_adb_bootstrap_android_studio_resolves_host_docker_internal(monkeypatch, capsys):
    import importlib.util
    from pathlib import Path
    module_path = Path(__file__).resolve().parents[2] / "analysis-engine" / "app" / "adb_bootstrap.py"
    spec = importlib.util.spec_from_file_location("adb_bootstrap", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    
    monkeypatch.setenv("ADB_HOST", "host.docker.internal")
    monkeypatch.setenv("ADB_PORT", "5555")
    monkeypatch.setenv("SANDBOX_PROVIDER", "android_studio")
    
    # Mock check_tcp to fail so it doesn't wait
    monkeypatch.setattr(mod, "check_tcp", lambda h, p, t=3: False)
    
    res = mod.bootstrap_adb_connect(max_attempts=1, retry_sleep_seconds=0)
    assert res == 0
    captured = capsys.readouterr().out
    assert "target=host.docker.internal:5555" in captured
    assert "provider=android_avd" in captured
    assert "tcp_connect=FAIL" in captured

def test_adb_bootstrap_device_serial_overrides(monkeypatch, capsys):
    import importlib.util
    from pathlib import Path
    module_path = Path(__file__).resolve().parents[2] / "analysis-engine" / "app" / "adb_bootstrap.py"
    spec = importlib.util.spec_from_file_location("adb_bootstrap", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    
    monkeypatch.setenv("ADB_HOST", "192.168.56.101")
    monkeypatch.setenv("DEVICE_SERIAL", "192.168.56.200:5555")
    monkeypatch.setenv("SANDBOX_PROVIDER", "genymotion")
    monkeypatch.setattr(mod, "check_tcp", lambda h, p, t=3: False)
    
    res = mod.bootstrap_adb_connect(max_attempts=1, retry_sleep_seconds=0)
    captured = capsys.readouterr().out
    assert "target=192.168.56.200:5555" in captured

def test_adb_bootstrap_offline_device_not_ready(monkeypatch, capsys):
    import importlib.util
    from pathlib import Path
    module_path = Path(__file__).resolve().parents[2] / "analysis-engine" / "app" / "adb_bootstrap.py"
    spec = importlib.util.spec_from_file_location("adb_bootstrap", module_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    
    monkeypatch.setattr(mod, "check_tcp", lambda h, p, t=3: False)
    
    class MockProvider:
        name = "auto"
        def list_devices(self):
            class D:
                serial = "emulator-5554"
                state = "offline"
            return [D()]
        def select_device(self, s):
            class D:
                serial = "emulator-5554"
                state = "offline"
            return D()
            
    monkeypatch.setattr(mod, "get_sandbox_provider", lambda c: MockProvider())
    
    res = mod.bootstrap_adb_connect(max_attempts=1, retry_sleep_seconds=0)
    captured = capsys.readouterr().out
    assert "state=offline" in captured
    assert "sandbox=UNAVAILABLE" in captured
