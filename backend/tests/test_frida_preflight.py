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


def _preflight_source() -> str:
    """
    Source of the device-session preflight.

    run_frida_analysis was split: it now acquires the per-device lock and
    delegates the install/instrument/close cycle to _run_device_session, which
    is where the SELinux and adb-root preflight lives. Inspect both so the
    assertions below track the behaviour rather than one function name.
    """
    return (
        inspect.getsource(frida_sandbox.run_frida_analysis)
        + inspect.getsource(frida_sandbox._run_device_session)
    )


def test_sandbox_makes_selinux_permissive_before_attaching():
    """The preflight must detect Enforcing and drop to Permissive."""
    src = _preflight_source()
    assert "getenforce" in src, "sandbox must check SELinux mode"
    assert "setenforce 0" in src, "sandbox must set the analysis AVD permissive"


def test_sandbox_requests_adb_root_before_attaching():
    src = _preflight_source()
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
    SELinux must be relaxed before Frida attach. Preflight lives in
    SandboxProvider.connect() (ensure_selinux_permissive → ensure_frida),
    with a second hardening pass in _run_device_session for legacy paths.
    """
    from sudarshan_core.sandbox.provider import SandboxProvider

    connect_src = inspect.getsource(SandboxProvider.connect)
    assert connect_src.index("ensure_selinux_permissive") < connect_src.index(
        "ensure_frida"
    ), "SELinux must be configured before Frida verification in SandboxProvider.connect"

    session_src = inspect.getsource(frida_sandbox._run_device_session)
    assert "getenforce" in session_src
    assert "setenforce 0" in session_src
