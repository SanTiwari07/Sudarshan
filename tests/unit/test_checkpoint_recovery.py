"""Crash recovery: re-hydrate a session without re-executing completed work.

The load-bearing property is not "state comes back" - it is that recovery is
**idempotent**. The verdict is computed from evidence counts, so a resume that
re-ran a completed goal or re-imported evidence it already held would inflate
the score of a sample that did nothing new.
"""

import json

import pytest

from sudarshan_core.engines.agentic.agent_memory import AgentMemory, CheckpointSnapshot
from sudarshan_core.engines.agentic.goal_tracker import GoalStatus, GoalTracker
from sudarshan_core.engines.session_manager import DynamicAnalysisSession, SessionState


@pytest.fixture
def artifacts(tmp_path, monkeypatch):
    """Isolate every checkpoint and evidence DB into a temp tree."""
    monkeypatch.setenv("SUDARSHAN_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


def _worked_memory() -> AgentMemory:
    memory = AgentMemory()
    memory.advance_iteration()
    memory.advance_iteration()
    memory.register_screen("hash-login", "com.evil/.LoginActivity")
    memory.register_screen("hash-home", "com.evil/.HomeActivity")
    memory.record_action(
        tool="click_text",
        target="Login",
        goal_name="Launch Application",
        reasoning="open the app",
        success=True,
    )
    memory.record_permission_granted("android.permission.RECEIVE_SMS")
    memory.record_frida_events([{"hook": "SmsManager.sendTextMessage"}], "SMS Interception")
    return memory


# ── Snapshot ───────────────────────────────────────────────────────────────


def test_snapshot_captures_resumable_state():
    snapshot = _worked_memory().create_snapshot(
        satisfied_goals=["Launch Application"], screenshot_index=7
    )
    assert snapshot.iteration == 2
    assert snapshot.satisfied_goals == ["Launch Application"]
    assert snapshot.screenshot_index == 7
    assert len(snapshot.visited_screens) == 2
    assert snapshot.frida_events_captured == 1


def test_snapshot_round_trips_through_json():
    """Checkpoints cross process - and sometimes host - boundaries."""
    snapshot = _worked_memory().create_snapshot(satisfied_goals=["Launch Application"])
    revived = CheckpointSnapshot.from_dict(
        json.loads(json.dumps(snapshot.to_dict(), ensure_ascii=False))
    )
    assert revived.to_dict() == snapshot.to_dict()


def test_restore_rehydrates_memory():
    snapshot = _worked_memory().create_snapshot(satisfied_goals=["Launch Application"])
    fresh = AgentMemory()
    assert fresh.restore_snapshot(snapshot.to_dict()) is True
    assert fresh.iteration == 2
    assert set(fresh.visited_screens) == {"hash-login", "hash-home"}
    assert "android.permission.RECEIVE_SMS" in fresh.permissions_granted


def test_restoring_twice_does_not_duplicate_state():
    snapshot = _worked_memory().create_snapshot(satisfied_goals=["Launch Application"])
    fresh = AgentMemory()
    fresh.restore_snapshot(snapshot.to_dict())
    fresh.restore_snapshot(snapshot.to_dict())
    assert len(fresh.visited_screens) == 2


def test_restore_of_empty_snapshot_is_refused():
    assert AgentMemory().restore_snapshot({}) is False


# ── Session lifecycle ──────────────────────────────────────────────────────


def test_checkpoint_survives_process_death(artifacts):
    memory = _worked_memory()
    tracker = GoalTracker()
    tracker.get_goal_by_name("Launch Application").status = GoalStatus.COMPLETED
    satisfied = [g.name for g in tracker.goals if g.status == GoalStatus.COMPLETED]

    session = DynamicAnalysisSession("case-1", "com.evil.dropper")
    session.start()
    path = session.save_checkpoint(
        memory.create_snapshot(satisfied_goals=satisfied).to_dict()
    )
    assert path is not None and path.is_file()

    # New process: nothing in memory.
    memory2, tracker2 = AgentMemory(), GoalTracker()
    session2 = DynamicAnalysisSession("case-1", "com.evil.dropper")
    snapshot = session2.recover_from_checkpoint(memory=memory2, goal_tracker=tracker2)

    assert snapshot is not None
    assert session2.state is SessionState.RECOVERED
    assert session2.recovered_from_snapshot is True
    assert memory2.iteration == 2
    assert len(memory2.visited_screens) == 2


def test_completed_goals_are_not_re_executed(artifacts):
    memory = _worked_memory()
    tracker = GoalTracker()
    tracker.get_goal_by_name("Launch Application").status = GoalStatus.COMPLETED

    session = DynamicAnalysisSession("case-2", "com.evil.dropper")
    session.save_checkpoint(
        memory.create_snapshot(satisfied_goals=["Launch Application"]).to_dict()
    )

    tracker2 = GoalTracker()
    assert tracker2.next_priority_goal().name == "Launch Application"

    DynamicAnalysisSession("case-2", "com.evil.dropper").recover_from_checkpoint(
        memory=AgentMemory(), goal_tracker=tracker2
    )
    # The resumed run moves on rather than re-driving work already done.
    assert tracker2.get_goal_by_name("Launch Application").status is GoalStatus.COMPLETED
    assert tracker2.next_priority_goal().name != "Launch Application"


def test_evidence_survives_a_crash_and_is_not_double_counted(artifacts):
    session = DynamicAnalysisSession("case-3", "com.evil.dropper")
    session.evidence_store._on_event(
        {"event_type": "FRIDA_HOOK", "hook": "WindowManager.addView", "args": ["overlay"]}
    )
    db_path = session.evidence_store.db_path
    assert db_path is not None and db_path.is_file()
    original = session.evidence_store.count()
    assert original > 0

    session2 = DynamicAnalysisSession("case-3", "com.evil.dropper")
    session2.evidence_store._records.clear()
    recovered = session2.evidence_store.recover_records(db_path)
    assert recovered == original

    # Recovering again must add nothing - the verdict depends on these counts.
    assert session2.evidence_store.recover_records(db_path) == 0
    assert session2.evidence_store.count() == original


def test_missing_checkpoint_fails_safe(artifacts):
    session = DynamicAnalysisSession("never-ran", "com.x")
    assert session.recover_from_checkpoint() is None
    assert session.state is SessionState.FAILED


def test_truncated_checkpoint_fails_safe(artifacts):
    session = DynamicAnalysisSession("case-4", "com.x")
    session.save_checkpoint(AgentMemory().create_snapshot().to_dict())
    session.checkpoint_file_path.write_text('{"session_id": "case-4", "snap', encoding="utf-8")

    session2 = DynamicAnalysisSession("case-4", "com.x")
    assert session2.recover_from_checkpoint() is None
    assert session2.state is SessionState.FAILED


def test_empty_snapshot_is_not_written(artifacts):
    session = DynamicAnalysisSession("case-5", "com.x")
    assert session.save_checkpoint({}) is None
    assert not session.checkpoint_file_path.is_file()


def test_session_id_cannot_escape_the_checkpoint_directory(artifacts):
    """Session ids reach this from request payloads."""
    session = DynamicAnalysisSession("../../etc/passwd", "com.x")
    assert ".." not in session.checkpoint_file_path.name
    assert artifacts in session.checkpoint_file_path.parents


def test_output_dir_is_portable(artifacts):
    """The old default was `/tmp/...`, which is not a path on Windows."""
    session = DynamicAnalysisSession("case-6", "com.x")
    assert session.output_dir.is_absolute()
    assert session.output_dir.is_dir()
    assert artifacts in session.output_dir.parents
