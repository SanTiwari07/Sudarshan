"""
Sandbox abstraction layer verification tests.

Covers device detection, ADB connection, root, Frida, provider selection,
structured errors, and Genymotion vs Android Studio state profiles - without
requiring a live device (subprocess/ADB mocked).
"""

from __future__ import annotations

import os
from typing import List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from sudarshan_core.sandbox import (
    ADBUnavailable,
    DeviceNotFound,
    FridaUnavailable,
    RootUnavailable,
    SandboxNotRooted,
    SandboxOffline,
    clear_sandbox_provider_cache,
    get_sandbox_provider,
    load_sandbox_config,
)
from sudarshan_core.sandbox.android_studio import AndroidStudioProvider
from sudarshan_core.sandbox.config import SandboxConfig
from sudarshan_core.sandbox.genymotion import GenymotionProvider
from sudarshan_core.sandbox.types import ConnectionResult, DeviceInfo


@pytest.fixture(autouse=True)
def _clear_provider_cache(monkeypatch):
    # Isolate from host shell leftovers (e.g. ANDROID_SANDBOX_PROVIDER=auto)
    for key in (
        "ANDROID_SANDBOX_PROVIDER",
        "ANDROID_DEVICE_SERIAL",
        "FRIDA_SERVER_DIR",
        "FRIDA_VERSION",
    ):
        monkeypatch.delenv(key, raising=False)
    clear_sandbox_provider_cache()
    yield
    clear_sandbox_provider_cache()


@pytest.fixture
def geny_cfg(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "genymotion")
    monkeypatch.setenv("ADB_HOST", "")
    monkeypatch.setenv("ADB_PORT", "5555")
    monkeypatch.setenv("DEVICE_SERIAL", "")
    monkeypatch.setenv("FRIDA_PORT", "27055")
    monkeypatch.setenv("AUTO_CONNECT", "true")
    monkeypatch.setenv("ROOT_REQUIRED", "true")
    clear_sandbox_provider_cache()
    return load_sandbox_config()


def _adb_sequence(responses: List[Tuple[bool, str]]):
    """Return a side_effect that yields (ok, out) pairs then repeats last."""
    it = iter(responses)

    def _side(*args, **kwargs):
        try:
            return next(it)
        except StopIteration:
            return responses[-1]

    return _side


# ── Config / factory ──────────────────────────────────────────────────────────


def test_load_sandbox_config_defaults(monkeypatch):
    for key in (
        "SANDBOX_PROVIDER", "ANDROID_SANDBOX_PROVIDER", "ADB_HOST", "ADB_PORT",
        "DEVICE_SERIAL", "ANDROID_DEVICE_SERIAL", "FRIDA_PORT", "AUTO_CONNECT",
        "ROOT_REQUIRED",
    ):
        monkeypatch.delenv(key, raising=False)
    cfg = load_sandbox_config()
    assert cfg.provider == "auto"
    assert cfg.adb_port == "5555"
    assert cfg.auto_connect is True
    assert cfg.root_required is True


def test_factory_returns_genymotion(geny_cfg):
    p = get_sandbox_provider(geny_cfg, force_new=True)
    assert isinstance(p, GenymotionProvider)
    assert p.name == "genymotion"


def test_factory_android_studio(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "android_studio")
    clear_sandbox_provider_cache()
    p = get_sandbox_provider(force_new=True)
    assert isinstance(p, AndroidStudioProvider)
    assert p.name == "android_avd"


def test_factory_aliases(monkeypatch):
    for alias in ("avd", "emulator", "androidstudio", "android_avd"):
        monkeypatch.setenv("SANDBOX_PROVIDER", alias)
        clear_sandbox_provider_cache()
        p = get_sandbox_provider(force_new=True)
        assert p.name == "android_avd"


# ── Device detection ──────────────────────────────────────────────────────────


def test_list_devices_parses_adb_devices(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    with patch.object(
        p,
        "adb",
        return_value=(
            True,
            "List of devices attached\n"
            "192.168.56.101:5555\tdevice\n"
            "emulator-5554\toffline\n",
        ),
    ):
        devices = p.list_devices()
    assert len(devices) == 1
    assert devices[0].serial == "192.168.56.101:5555"
    assert devices[0].ip == "192.168.56.101"


def test_select_device_uses_device_serial(geny_cfg, monkeypatch):
    monkeypatch.setenv("DEVICE_SERIAL", "192.168.56.101:5555")
    cfg = load_sandbox_config()
    p = GenymotionProvider(cfg)
    with patch.object(
        p,
        "list_devices",
        return_value=[
            DeviceInfo(serial="emulator-5554", provider="genymotion"),
            DeviceInfo(serial="192.168.56.101:5555", provider="genymotion"),
        ],
    ):
        d = p.select_device()
    assert d.serial == "192.168.56.101:5555"


def test_select_device_missing_falls_back(geny_cfg, monkeypatch):
    monkeypatch.setenv("DEVICE_SERIAL", "missing-serial")
    cfg = load_sandbox_config()
    p = GenymotionProvider(cfg)
    with patch.object(
        p,
        "list_devices",
        return_value=[DeviceInfo(serial="192.168.56.101:5555")],
    ):
        d = p.select_device()
    assert d.serial == "192.168.56.101:5555"


def test_select_device_none_online(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    with patch.object(p, "list_devices", return_value=[]):
        with pytest.raises(DeviceNotFound):
            p.select_device()


# ── ADB connection / auto-connect ─────────────────────────────────────────────


def test_auto_connect_calls_adb_connect(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "genymotion")
    monkeypatch.setenv("ADB_HOST", "192.168.56.102")
    monkeypatch.setenv("ADB_PORT", "5555")
    monkeypatch.setenv("AUTO_CONNECT", "true")
    cfg = load_sandbox_config()
    p = GenymotionProvider(cfg)
    calls = []

    def fake_adb(*args, **kwargs):
        calls.append(args)
        if args and args[0] == "connect":
            return True, "connected to 192.168.56.102:5555"
        if args and args[0] == "devices":
            # First probe in _maybe_tcp_connect sees nothing; after connect, device appears.
            if not any(c and c[0] == "connect" for c in calls[:-1]):
                return True, "List of devices attached\n"
            return True, "List of devices attached\n192.168.56.102:5555\tdevice\n"
        return True, ""

    with patch.object(p, "adb", side_effect=fake_adb):
        devices = p.list_devices()
    assert any(c[0] == "connect" for c in calls)
    assert devices[0].serial == "192.168.56.102:5555"


def test_auto_connect_skips_docker_host_alias(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "auto")
    monkeypatch.setenv("ADB_HOST", "host.docker.internal")
    monkeypatch.setenv("AUTO_CONNECT", "true")
    cfg = load_sandbox_config()
    p = GenymotionProvider(cfg)
    calls = []

    def fake_adb(*args, **kwargs):
        calls.append(args)
        if args and args[0] == "devices":
            return True, "List of devices attached\nemulator-5554\tdevice\n"
        return True, ""

    with patch.object(p, "adb", side_effect=fake_adb):
        p.list_devices()
    assert not any(c and c[0] == "connect" for c in calls)


def test_adb_unavailable_on_connect(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    with patch.object(p, "find_adb", return_value=None):
        result = p.connect()
    assert result.ok is False
    assert result.error_code == "ADB_UNAVAILABLE"


# ── Root ──────────────────────────────────────────────────────────────────────


def test_ensure_root_success(geny_cfg):
    p = GenymotionProvider(geny_cfg)

    def fake_adb(*args, **kwargs):
        joined = " ".join(args)
        if "root" in args:
            return True, "restarting adbd as root"
        if "whoami" in joined:
            return True, "root"
        return True, ""

    with patch.object(p, "adb", side_effect=fake_adb):
        with patch.object(p, "adb_shell", side_effect=lambda s, c, timeout=30: (True, "root")):
            assert p.ensure_root("192.168.56.101:5555") is True


def test_ensure_root_failure_raises_sandbox_not_rooted(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    with patch.object(p, "adb", return_value=(False, "error")):
        with patch.object(p, "adb_shell", return_value=(True, "shell")):
            with pytest.raises(RootUnavailable) as ei:
                p.ensure_root("serial")
    assert ei.value.code == "ROOT_UNAVAILABLE"
    assert SandboxNotRooted is RootUnavailable


# ── Frida ─────────────────────────────────────────────────────────────────────


def test_ensure_frida_already_running(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    with patch.object(
        p,
        "adb_shell",
        return_value=(True, "root  123  1  ... sudarshan_agent_srv"),
    ):
        with patch.object(p, "adb", return_value=(True, "")):
            with patch.object(
                p,
                "get_device_info",
                return_value=DeviceInfo(serial="serial", abi="x86_64"),
            ):
                status = p.ensure_frida("serial")
    assert status.available is True
    assert status.running is True
    assert status.restarted is False


def test_ensure_frida_restarts(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    calls = {"n": 0}

    # The agent is detected by process NAME (pidof, then `ps -A -o PID,NAME`),
    # never by `pgrep -f`, which would also match the shell running the probe.
    started = {"yes": False}

    def fake_shell(serial, command, timeout=30):
        calls["n"] += 1
        if command.startswith("ls "):
            return True, "/data/local/tmp/sudarshan_agent_srv"
        if "pidof" in command:
            return (True, "4242") if started["yes"] else (True, "")
        if "ps -A" in command:
            if started["yes"]:
                return True, "PID NAME\n 4242 sudarshan_agent"
            return True, "PID NAME"
        if "pkill" in command:
            return True, ""
        # Anything else is the start command itself.
        started["yes"] = True
        return True, ""

    with patch.object(p, "adb_shell", side_effect=fake_shell):
        with patch.object(p, "adb", return_value=(True, "")):
            with patch.object(
                p,
                "get_device_info",
                return_value=DeviceInfo(serial="serial", abi="x86_64"),
            ):
                status = p.ensure_frida("serial", restart_if_needed=True, push_if_missing=False)
    assert status.available is True
    assert status.restarted is True


def test_verify_frida_unavailable(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    with patch.object(p, "adb_shell", return_value=(True, "")):
        with patch.object(
            p,
            "get_device_info",
            return_value=DeviceInfo(serial="serial", abi="x86_64"),
        ):
            status = p.verify_frida("serial")
    assert status.available is False


# ── Full connect handshake ────────────────────────────────────────────────────


def test_connect_success_structured(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    device = DeviceInfo(
        serial="192.168.56.101:5555",
        android_version="11",
        api_level="30",
        abi="x86_64",
        provider="genymotion",
    )

    with patch.object(p, "find_adb", return_value="/usr/bin/adb"):
        with patch.object(p, "select_device", return_value=device):
            with patch.object(p, "verify_online", return_value=True):
                with patch.object(p, "get_device_info", return_value=device):
                    with patch.object(p, "ensure_root"):
                        with patch.object(p, "ensure_selinux_permissive", return_value="Permissive"):
                            with patch.object(
                                p,
                                "ensure_frida",
                                return_value=MagicMock(
                                    available=True,
                                    running=True,
                                    host_version="17.16.4",
                                    message="ok",
                                    to_dict=lambda: {"available": True},
                                ),
                            ):
                                result = p.connect()

    assert isinstance(result, ConnectionResult)
    assert result.ok is True
    assert result.device.serial == "192.168.56.101:5555"
    assert result.connection_time_ms >= 0
    stage_names = [s["stage"] for s in result.stages]
    assert "adb" in stage_names
    assert "root" in stage_names
    assert "frida" in stage_names


def test_connect_never_raises(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    with patch.object(p, "find_adb", side_effect=RuntimeError("boom")):
        result = p.connect()
    assert result.ok is False
    assert result.error_code == "SANDBOX_ERROR"


# ── State profiles (Genymotion vs Studio) ─────────────────────────────────────


def test_genymotion_battery_uses_dumpsys_not_emu(geny_cfg):
    p = GenymotionProvider(geny_cfg)
    seen = []

    def fake_adb(*args, **kwargs):
        seen.append(args)
        return True, ""

    with patch.object(p, "adb", side_effect=fake_adb):
        assert p.apply_state_profile("serial", "battery_low") is True
    flat = [" ".join(a) for a in seen]
    assert any("dumpsys" in f and "battery" in f for f in flat)
    assert not any(" emu " in f or f.endswith("emu") or "emu" in f.split()[:5] for f in flat)


def test_android_studio_gps_uses_emu():
    cfg = SandboxConfig(provider="android_studio")
    p = AndroidStudioProvider(cfg)
    seen = []

    def fake_adb(*args, **kwargs):
        seen.append(args)
        return True, ""

    with patch.object(p, "adb", side_effect=fake_adb):
        assert p.apply_state_profile("emulator-5554", "gps_active") is True
    assert any(len(a) >= 2 and a[2] == "emu" for a in seen)


# ── DeviceStateSimulator delegates to provider ────────────────────────────────


def test_device_state_simulator_delegates():
    from sudarshan_core.engines.device_state_simulator import DeviceStateSimulator

    mock_provider = MagicMock()
    mock_provider.apply_state_profile.return_value = True
    mock_provider.reset_state.return_value = True
    sim = DeviceStateSimulator("192.168.56.101:5555", provider=mock_provider)
    assert sim.apply_profile("wifi_off") is True
    mock_provider.apply_state_profile.assert_called_once_with(
        "192.168.56.101:5555", "wifi_off"
    )
    assert sim.reset() is True


# ── frida_sandbox integration (provider.connect) ──────────────────────────────


def test_run_frida_analysis_maps_sandbox_offline(monkeypatch, geny_cfg):
    import asyncio
    from sudarshan_core.engines import frida_sandbox as fs

    mock_provider = MagicMock()
    mock_provider.name = "genymotion"
    mock_provider.connect.return_value = ConnectionResult(
        ok=False,
        error_code="DEVICE_NOT_FOUND",
        error_message="No online devices",
    )
    monkeypatch.setattr(fs, "_get_provider", lambda: mock_provider)

    async def _fast_sleep(_):
        return None

    monkeypatch.setattr(asyncio, "sleep", _fast_sleep)
    result = asyncio.run(fs.run_frida_analysis("/tmp/fake.apk", package_name="com.fake"))
    assert result["available"] is False
    assert result["error_code"] == "DEVICE_NOT_FOUND"
    assert "No online devices" in result["error"]


def test_get_connected_emulators_delegates(monkeypatch, geny_cfg):
    from sudarshan_core.engines import frida_sandbox as fs

    mock_provider = MagicMock()
    mock_provider.list_devices.return_value = [
        DeviceInfo(serial="192.168.56.101:5555"),
    ]
    monkeypatch.setattr(fs, "_get_provider", lambda: mock_provider)
    assert fs.get_connected_emulators() == ["192.168.56.101:5555"]


# ── Exception codes ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "exc_cls,code",
    [
        (SandboxOffline, "SANDBOX_OFFLINE"),
        (ADBUnavailable, "ADB_UNAVAILABLE"),
        (DeviceNotFound, "DEVICE_NOT_FOUND"),
        (FridaUnavailable, "FRIDA_UNAVAILABLE"),
        (RootUnavailable, "ROOT_UNAVAILABLE"),
    ],
)
def test_exception_codes(exc_cls, code):
    e = exc_cls("msg")
    assert e.code == code
    assert e.to_dict()["error"] == code


# ── Compatibility matrix helpers ──────────────────────────────────────────────


@pytest.mark.parametrize("api,abi", [("29", "x86"), ("30", "x86_64"), ("29", "x86_64"), ("30", "x86")])
def test_device_info_supports_target_apis(api, abi):
    info = DeviceInfo(
        serial="test",
        android_version="10" if api == "29" else "11",
        api_level=api,
        abi=abi,
        provider="genymotion",
    )
    assert info.api_level in ("29", "30")
    assert info.abi in ("x86", "x86_64")
    d = info.to_dict()
    assert d["api_level"] == api
