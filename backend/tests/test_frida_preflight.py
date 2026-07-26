"""
Regression tests for the Frida attach failure.

Symptom: every dynamic run returned INSTRUMENTATION_FAILED with
    "Frida attach failed. Ensure frida-server is running on emulator."
Cause: frida-server WAS running. SELinux is Enforcing by default on Android
15+, which denies the ptrace that Frida injection needs — even for uid 0 — so
`device.attach(pid)` raised PermissionDeniedError on a process that was
demonstrably running. The error message blamed the wrong component and cost
real debugging time.
"""

import inspect

from sudarshan_core.engines import frida_sandbox


def test_sandbox_makes_selinux_permissive_before_attaching():
    """The preflight must detect Enforcing and drop to Permissive."""
    src = inspect.getsource(frida_sandbox.run_frida_analysis)
    assert "getenforce" in src, "sandbox must check SELinux mode"
    assert "setenforce 0" in src, "sandbox must set the analysis AVD permissive"


def test_sandbox_requests_adb_root_before_attaching():
    src = inspect.getsource(frida_sandbox.run_frida_analysis)
    assert '"root"' in src, "adbd must be root for frida to inject"


def test_attach_failure_message_does_not_blame_frida_server_blindly():
    """
    The old message asserted a cause it had not checked. A failure report that
    names the wrong component is worse than a generic one.
    """
    src = inspect.getsource(frida_sandbox.FridaSession.run)
    assert "Ensure frida-server is running on emulator." not in src, (
        "the misleading fixed message must not come back"
    )
    # It must consider the real alternatives instead.
    assert "getenforce" in src, "failure path should report SELinux state"
    assert "_resolve_pid" in src, "failure path should distinguish launch vs attach"


def test_selinux_preflight_runs_before_frida_server_check():
    """
    Ordering matters: starting frida-server while SELinux still blocks ptrace
    produces a healthy-looking server and a failing attach, which is exactly the
    misdiagnosis this fix removes.
    """
    src = inspect.getsource(frida_sandbox.run_frida_analysis)
    assert src.index("getenforce") < src.index("Checking frida-server status"), (
        "SELinux preflight must precede the frida-server check"
    )
