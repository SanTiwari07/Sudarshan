"""Regression tests for sandbox containment policy."""

import pytest

from sudarshan_core.sandbox.config import SandboxConfig
from sudarshan_core.security.sandbox_containment import (
    ContainmentViolation,
    audit_sandbox_connectivity,
    build_frida_start_command,
    enforce_connectivity_policy,
    frida_listen_host,
    validate_adb_invocation,
)


def test_genymotion_rejects_host_docker_internal():
    cfg = SandboxConfig(provider="genymotion", adb_host="host.docker.internal", adb_port="5555")
    findings = audit_sandbox_connectivity(cfg)
    codes = {f.code for f in findings if f.severity == "error"}
    assert "GENYMOTION_HOST_DOCKER_INTERNAL" in codes


def test_genymotion_accepts_host_only_ip():
    cfg = SandboxConfig(provider="genymotion", adb_host="192.168.56.101", adb_port="5555")
    errors = [f for f in audit_sandbox_connectivity(cfg) if f.severity == "error"]
    assert not errors


def test_strict_mode_raises_on_bad_genymotion_config(monkeypatch):
    monkeypatch.setenv("SANDBOX_CONTAINMENT_STRICT", "true")
    cfg = SandboxConfig(provider="genymotion", adb_host="host.docker.internal")
    with pytest.raises(ContainmentViolation) as exc:
        enforce_connectivity_policy(cfg)
    assert exc.value.code == "GENYMOTION_HOST_DOCKER_INTERNAL"


def test_frida_listen_host_forces_loopback_when_unsafe(monkeypatch):
    monkeypatch.setenv("FRIDA_LISTEN_HOST", "0.0.0.0")
    assert frida_listen_host() == "127.0.0.1"


def test_build_frida_start_command_uses_loopback():
    cmd = build_frida_start_command("/data/local/tmp/frida-server", "27055")
    assert "127.0.0.1:27055" in cmd
    assert "0.0.0.0" not in cmd


def test_adb_listen_all_blocked():
    with pytest.raises(ContainmentViolation):
        validate_adb_invocation(["-a", "nodaemon", "server"])


def test_adb_tcpip_blocked():
    with pytest.raises(ContainmentViolation):
        validate_adb_invocation(["tcpip", "5555"])


def test_adb_tcpip_after_serial_is_blocked():
    with pytest.raises(ContainmentViolation):
        validate_adb_invocation(["-s", "192.168.56.101:5555", "tcpip", "5555"])


def test_adb_remote_server_host_flag_blocked(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "genymotion")
    with pytest.raises(ContainmentViolation):
        validate_adb_invocation(["-H", "host.docker.internal", "devices"])


def test_genymotion_rejects_loopback_adb_host():
    cfg = SandboxConfig(provider="genymotion", adb_host="127.0.0.1", adb_port="5555")
    codes = {f.code for f in audit_sandbox_connectivity(cfg) if f.severity == "error"}
    assert "GENYMOTION_ADB_HOST_LOOPBACK" in codes


def test_frida_strict_rejects_lan_bind(monkeypatch):
    monkeypatch.setenv("SANDBOX_CONTAINMENT_STRICT", "true")
    monkeypatch.setenv("FRIDA_LISTEN_HOST", "192.168.56.101")
    with pytest.raises(ContainmentViolation):
        frida_listen_host()


def test_adb_connect_host_bridge_blocked_for_genymotion(monkeypatch):
    monkeypatch.setenv("SANDBOX_PROVIDER", "genymotion")
    with pytest.raises(ContainmentViolation):
        validate_adb_invocation(["connect", "host.docker.internal:5555"])


def test_run_adb_gateway_enforces_policy(tmp_path):
    from sudarshan_core.security.adb_gateway import run_adb

    fake_adb = tmp_path / "adb.cmd"
    fake_adb.write_text("rem stub")
    with pytest.raises(ContainmentViolation):
        run_adb(str(fake_adb), ["tcpip", "5555"])

