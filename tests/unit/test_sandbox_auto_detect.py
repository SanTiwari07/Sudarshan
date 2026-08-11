"""
Unit tests for emulator-agnostic sandbox detection / Frida ABI resolution.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from sudarshan_core.sandbox import (
    clear_sandbox_provider_cache,
    get_sandbox_provider,
    load_sandbox_config,
)
from sudarshan_core.sandbox.auto import AutoDetectProvider, PhysicalDeviceProvider
from sudarshan_core.sandbox.android_studio import AndroidStudioProvider
from sudarshan_core.sandbox.device import (
    detect_provider_from_props,
    parse_adb_devices_l,
    rank_devices,
    select_sandbox_device,
    transport_for_serial,
)
from sudarshan_core.sandbox.frida_assets import (
    frida_arch_for_abi,
    locate_frida_server,
    missing_binary_message,
)
from sudarshan_core.sandbox.types import DeviceInfo


@pytest.fixture(autouse=True)
def _clear_cache(monkeypatch):
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


def test_load_sandbox_config_defaults_auto(monkeypatch):
    for key in (
        "SANDBOX_PROVIDER",
        "ANDROID_SANDBOX_PROVIDER",
        "ADB_HOST",
        "DEVICE_SERIAL",
        "ANDROID_DEVICE_SERIAL",
    ):
        monkeypatch.delenv(key, raising=False)
    cfg = load_sandbox_config()
    assert cfg.provider == "auto"


def test_android_device_serial_alias(monkeypatch):
    monkeypatch.delenv("DEVICE_SERIAL", raising=False)
    monkeypatch.setenv("ANDROID_DEVICE_SERIAL", "emulator-5554")
    monkeypatch.setenv("SANDBOX_PROVIDER", "auto")
    cfg = load_sandbox_config()
    assert cfg.device_serial == "emulator-5554"


def test_factory_auto_default(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "auto")
    clear_sandbox_provider_cache()
    p = get_sandbox_provider(force_new=True)
    assert isinstance(p, AutoDetectProvider)


def test_factory_android_avd_alias(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "android_avd")
    clear_sandbox_provider_cache()
    p = get_sandbox_provider(force_new=True)
    assert isinstance(p, AndroidStudioProvider)
    assert p.name == "android_avd"


def test_factory_physical(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "physical")
    clear_sandbox_provider_cache()
    p = get_sandbox_provider(force_new=True)
    assert isinstance(p, PhysicalDeviceProvider)


@pytest.mark.parametrize(
    "serial,expected",
    [
        ("emulator-5554", "emulator"),
        ("emulator-5556", "emulator"),
        ("192.168.56.102:5555", "tcp"),
        ("10.0.0.5:5555", "tcp"),
        ("R58MABCDEF", "usb"),
    ],
)
def test_transport_for_serial(serial, expected):
    assert transport_for_serial(serial) == expected


def test_detect_genymotion_from_props():
    assert (
        detect_provider_from_props(
            serial="192.168.56.102:5555",
            manufacturer="Genymotion",
            model="Phone",
            product="vbox86p",
            device="vbox86p",
        )
        == "genymotion"
    )


def test_detect_avd_from_serial():
    assert (
        detect_provider_from_props(
            serial="emulator-5554",
            manufacturer="Google",
            model="sdk_gphone64_x86_64",
            product="sdk_gphone64_x86_64",
        )
        == "android_avd"
    )


def test_detect_physical():
    assert (
        detect_provider_from_props(
            serial="R58MXXXXXXXX",
            manufacturer="samsung",
            model="SM-G991B",
            product="o1s",
        )
        == "physical"
    )


def test_parse_adb_devices_l():
    raw = (
        "List of devices attached\n"
        "192.168.56.102:5555    device product:vbox86p model:Phone device:vbox86p\n"
        "emulator-5554          device product:sdk_gphone64_x86_64 model:sdk_gphone64_x86_64\n"
        "emulator-5556          offline\n"
    )
    devices = parse_adb_devices_l(raw)
    assert len(devices) == 2
    assert devices[0]["serial"] == "192.168.56.102:5555"
    assert devices[0]["product"] == "vbox86p"
    assert devices[1]["serial"] == "emulator-5554"


def test_select_prefers_emulator_over_physical():
    devices = [
        DeviceInfo(serial="R58M1", provider="physical", is_emulator=False, abi="arm64-v8a"),
        DeviceInfo(
            serial="emulator-5554",
            provider="android_avd",
            is_emulator=True,
            abi="x86_64",
            rooted=True,
        ),
    ]
    chosen = select_sandbox_device(devices, supported_abis=["x86_64"])
    assert chosen.serial == "emulator-5554"


def test_select_honors_preferred_serial():
    devices = [
        DeviceInfo(serial="emulator-5554", provider="android_avd", is_emulator=True),
        DeviceInfo(serial="192.168.56.102:5555", provider="genymotion", is_emulator=True),
    ]
    chosen = select_sandbox_device(devices, preferred_serial="192.168.56.102:5555")
    assert chosen.serial == "192.168.56.102:5555"


def test_select_none_raises_actionable():
    with pytest.raises(ValueError, match="No Android sandbox detected"):
        select_sandbox_device([])


def test_rank_prefers_rooted():
    devices = [
        DeviceInfo(serial="emulator-5556", provider="android_avd", is_emulator=True, rooted=False),
        DeviceInfo(serial="emulator-5554", provider="android_avd", is_emulator=True, rooted=True),
    ]
    ranked = rank_devices(devices)
    assert ranked[0].serial == "emulator-5554"


@pytest.mark.parametrize(
    "abi,arch",
    [
        ("x86_64", "x86_64"),
        ("x86", "x86"),
        ("arm64-v8a", "arm64"),
        ("armeabi-v7a", "arm"),
    ],
)
def test_frida_arch_mapping(abi, arch):
    assert frida_arch_for_abi(abi) == arch


def test_locate_frida_x86_64_in_repo():
    repo = Path(__file__).resolve().parents[2]
    spec = locate_frida_server("x86_64", repo_root=repo)
    # Repo ships the x86_64 binary used by Genymotion / most AVDs
    assert spec.frida_arch == "x86_64"
    assert spec.expected_name == "frida-server-17.16.4-android-x86_64"
    if (repo / "frida-server-17.16.4-android-x86_64").exists():
        assert spec.found is True


def test_missing_arm64_message_is_actionable():
    repo = Path(__file__).resolve().parents[2]
    spec = locate_frida_server("arm64-v8a", repo_root=repo, search_dirs=[repo / "does-not-exist"])
    msg = missing_binary_message(spec)
    assert "ABI: arm64-v8a" in msg
    assert "frida-server-17.16.4-android-arm64" in msg
    assert "Binary found: no" in msg


def test_list_devices_uses_devices_l(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "auto")
    monkeypatch.setenv("ADB_HOST", "")
    monkeypatch.setenv("AUTO_CONNECT", "false")
    clear_sandbox_provider_cache()
    p = get_sandbox_provider(force_new=True)

    def fake_adb(*args, **kwargs):
        if args[:2] == ("devices", "-l") or (args and args[0] == "devices" and "-l" in args):
            return (
                True,
                "List of devices attached\n"
                "192.168.56.102:5555    device product:vbox86p model:Phone device:vbox86p\n",
            )
        return True, ""

    with patch.object(p, "adb", side_effect=fake_adb):
        devices = p.list_devices(enrich=False)
    assert len(devices) == 1
    assert devices[0].serial == "192.168.56.102:5555"
    assert devices[0].provider == "genymotion"


def test_ensure_root_soft_when_not_required(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "auto")
    monkeypatch.setenv("ROOT_REQUIRED", "false")
    clear_sandbox_provider_cache()
    cfg = load_sandbox_config()
    p = AutoDetectProvider(cfg)

    with patch.object(p, "adb", return_value=(False, "adbd cannot run as root")):
        with patch.object(p, "adb_shell", return_value=(True, "shell")):
            assert p.ensure_root("emulator-5554") is False
