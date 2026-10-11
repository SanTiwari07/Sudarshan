"""
MultiStageEngine state transitions. MOCKED: run_frida_analysis, the device
list and the DeviceStateSimulator are stubbed - no emulator is involved.
"""

from __future__ import annotations

import pytest

import sudarshan_core.engines.multi_stage_engine as mse


class _Sim:
    def __init__(self, applied=None, raise_on=None):
        self.applied = applied or {}
        self.raise_on = raise_on
        self.calls = []
        self.resets = 0

    def apply_profile(self, profile):
        self.calls.append(profile)
        if profile == self.raise_on:
            raise RuntimeError("adb exploded")
        return self.applied.get(profile, True)

    def reset(self):
        self.resets += 1
        return True


def _result(status="EVENTS_CAPTURED", bfci=10.0, available=True, **kw):
    return {"available": available, "dynamic_status": status, "bfci": bfci, **kw}


@pytest.fixture
def engine(monkeypatch):
    monkeypatch.setattr(mse, "get_connected_emulators", lambda: ["emu-1"])
    monkeypatch.setattr(mse.asyncio, "sleep", _no_sleep)
    eng = mse.MultiStageEngine("/tmp/x.apk", device_serial="emu-1", package_name="com.x")
    eng.simulator = _Sim()
    return eng


async def _no_sleep(_s):
    return None


def _stub_runs(monkeypatch, by_stage):
    seen = []

    async def fake(apk, package_name=None, *, static_findings=None, stage_name=None):
        seen.append(stage_name)
        out = by_stage[stage_name]
        if isinstance(out, Exception):
            raise out
        return dict(out)

    monkeypatch.setattr(mse, "run_frida_analysis", fake)
    return seen


async def test_failed_dynamic_run_is_not_reported_as_success(engine, monkeypatch):
    _stub_runs(monkeypatch, {
        "fresh_install": _result("INSTRUMENTATION_FAILED", 0.0, error="no canary"),
        "sim_active": _result("EVENTS_CAPTURED", 30.0),
        "banking_apps": _result("RUNTIME_COMPLETED_NO_EVENTS", 0.0),
        "rebooted": _result("EMULATOR_UNAVAILABLE", 0.0, available=False),
    })
    out = await engine.run_all_stages()
    st = out["multi_stage_summary"]["stage_statuses"]
    assert st == {
        "fresh_install": "DYNAMIC_FAILED",
        "sim_active": "COMPLETED_WITH_EVENTS",
        "banking_apps": "COMPLETED_NO_EVENTS",
        "rebooted": "DYNAMIC_FAILED",
    }
    assert "success" not in st.values()
    assert out["stage"] == "sim_active" and out["bfci"] == 30.0
    rec = {r["stage"]: r for r in out["multi_stage_summary"]["stages"]}
    assert rec["fresh_install"]["error"]["message"] == "no canary"
    assert all(r["started_at"] and r["ended_at"] >= r["started_at"] for r in rec.values())
    assert rec["rebooted"]["limitations"] and "NOT rebooted" in rec["rebooted"]["limitations"][0]
    assert engine.simulator.resets == 2


async def test_failed_stage_never_becomes_primary(engine, monkeypatch):
    _stub_runs(monkeypatch, {
        "fresh_install": _result("INSTRUMENTATION_FAILED", 55.0),   # high bfci but unusable
        "sim_active": _result("EVENTS_CAPTURED", 12.0),
        "banking_apps": _result("EVENTS_CAPTURED", 12.0),
        "rebooted": _result("EVENTS_CAPTURED", 3.0),
    })
    out = await engine.run_all_stages()
    assert out["stage"] == "sim_active"          # tie -> earliest usable
    assert out["multi_stage_summary"]["usable_stages"] == ["sim_active", "banking_apps", "rebooted"]


async def test_profile_not_applied_skips_analysis_and_says_so(engine, monkeypatch):
    engine.simulator = _Sim(applied={"banking_apps": False})
    seen = _stub_runs(monkeypatch, {s["name"]: _result() for s in mse.STAGES})
    out = await engine.run_all_stages()
    assert "banking_apps" not in seen
    rec = {r["stage"]: r for r in out["multi_stage_summary"]["stages"]}
    assert rec["banking_apps"]["stage_status"] == "PROFILE_NOT_APPLIED"
    assert rec["banking_apps"]["profile_applied"] is False
    assert rec["sim_active"]["profile_applied"] is True
    assert rec["fresh_install"]["profile_applied"] is None


async def test_profile_exception_is_contained_and_device_reset(engine, monkeypatch):
    engine.simulator = _Sim(raise_on="sim_present")
    _stub_runs(monkeypatch, {s["name"]: _result() for s in mse.STAGES})
    out = await engine.run_all_stages()
    rec = {r["stage"]: r for r in out["multi_stage_summary"]["stages"]}
    assert rec["sim_active"]["stage_status"] == "ERROR"
    assert rec["sim_active"]["error"]["type"] == "RuntimeError"
    assert rec["banking_apps"]["stage_status"] == "COMPLETED_WITH_EVENTS"
    assert engine.simulator.resets == 2


async def test_disconnect_records_remaining_stages_as_skipped(engine, monkeypatch):
    calls = {"n": 0}

    def devices():
        calls["n"] += 1
        return ["emu-1"] if calls["n"] <= 2 else []

    monkeypatch.setattr(mse, "get_connected_emulators", devices)
    _stub_runs(monkeypatch, {s["name"]: _result() for s in mse.STAGES})
    out = await engine.run_all_stages()
    rec = {r["stage"]: r for r in out["multi_stage_summary"]["stages"]}
    assert [rec[s]["stage_status"] for s in ("banking_apps", "rebooted")] == ["SKIPPED", "SKIPPED"]
    assert rec["banking_apps"]["error"]["type"] == "DeviceDisconnected"
    assert "disconnected" in rec["rebooted"]["error"]["message"]
    assert len(out["multi_stage_summary"]["stages"]) == 4


async def test_all_stages_failing_returns_structured_unavailable_result(engine, monkeypatch):
    _stub_runs(monkeypatch, {s["name"]: RuntimeError("boom") for s in mse.STAGES})
    out = await engine.run_all_stages()
    assert out["available"] is False
    assert out["dynamic_status"] == "FAILED"
    assert out["runtime_attempted"] is True
    assert set(out["multi_stage_summary"]["stage_statuses"].values()) == {"ERROR"}


async def test_stage_name_and_static_findings_forwarded(monkeypatch):
    monkeypatch.setattr(mse, "get_connected_emulators", lambda: ["emu-1"])
    monkeypatch.setattr(mse.asyncio, "sleep", _no_sleep)
    eng = mse.MultiStageEngine("/a.apk", "emu-1", "com.x", static_findings={"permissions": ["P"]})
    eng.simulator = _Sim()
    got = []

    async def fake(apk, package_name=None, *, static_findings=None, stage_name=None):
        got.append((stage_name, static_findings))
        return _result()

    monkeypatch.setattr(mse, "run_frida_analysis", fake)
    await eng.run_all_stages()
    assert [g[0] for g in got] == [s["name"] for s in mse.STAGES]
    assert all(g[1] == {"permissions": ["P"]} for g in got)


def test_batch_runner_passes_arguments_by_name():
    import inspect
    import sudarshan_core.engines.batch_runner as br

    src = inspect.getsource(br.run_batch)
    assert "MultiStageEngine(apk_path=str(apk), device_serial=device_serial)" in src
