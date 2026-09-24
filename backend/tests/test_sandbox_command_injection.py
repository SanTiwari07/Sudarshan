import pytest
import shlex
import subprocess
from sudarshan_core.sandbox.provider import SandboxProvider
from sudarshan_core.sandbox.config import SandboxConfig

class DummyProvider(SandboxProvider):
    def _adb_candidates(self):
        return []
    def apply_state_profile(self, serial, profile):
        pass
    def reset_state(self, serial):
        return True

def test_package_installed_command_construction(monkeypatch):
    provider = DummyProvider(SandboxConfig())
    
    # We want to spy on what command is actually sent to adb_shell
    commands = []
    def fake_adb_shell(serial, cmd, timeout=30):
        commands.append(cmd)
        return True, "package:/data/app/test.apk"
        
    monkeypatch.setattr(provider, "adb_shell", fake_adb_shell)
    
    # Test malicious packages
    malicious = [
        "com.example;whoami",
        "com.example && whoami",
        "com.example | whoami",
        "com.example $(whoami)",
        "com.example `whoami`",
        "com.example'whoami",
        "com.example\"whoami",
    ]
    
    for mal in malicious:
        provider.package_installed("dummy_serial", mal)
        
    # Check that they are safely quoted
    for mal, cmd in zip(malicious, commands):
        quoted = shlex.quote(mal)
        assert cmd == f"pm path {quoted}", f"Command was not quoted correctly: {cmd}"
