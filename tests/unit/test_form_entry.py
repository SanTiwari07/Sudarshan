"""
SUDARSHAN - Multi-field form entry.

The defect class these cover: the explorer could fill a login box but not a
registration / personal-details / KYC form. Several independent faults
reinforced each other, and each is pinned here by the behaviour that was wrong
rather than by the shape of the code that was wrong.

Grouped in one module because they are one bug from the user's point of view -
"the app asks for name, email and phone and the walk gives up" - and a
regression in any one of them brings the whole symptom back.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.tool_executor import ToolExecutor  # noqa: E402


# ─── Harness ─────────────────────────────────────────────────────────────────

def _executor(package: str = "com.example.form"):
    """A ToolExecutor whose ADB channel records every argv it is handed."""
    calls: list[tuple[str, ...]] = []

    async def _record(*args: str):
        calls.append(args)
        return True, ""

    ex = ToolExecutor(device_serial="fixture-5554", package_name=package)
    ex._adb = AsyncMock(side_effect=_record)
    return ex, calls


def _argv(calls) -> list[str]:
    return [" ".join(str(a) for a in c) for c in calls]


# ─── F1: clearing a field before typing into it ──────────────────────────────

def test_type_text_never_emits_an_invalid_keycode():
    """
    `KEYCODE_CTRL_A` is not an Android keycode.

    android.view.KeyEvent defines KEYCODE_CTRL_LEFT / KEYCODE_CTRL_RIGHT and no
    per-letter chord, so `input keyevent KEYCODE_CTRL_A` returns "Unknown
    keycode" and clears nothing. The result was discarded, so the failure was
    silent and every re-entry APPENDED to the field:
    `user4f2a` -> `user4f2auser9c1b` -> ... which no email or phone validator
    will ever accept.
    """
    ex, calls = _executor()
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    assert not any("KEYCODE_CTRL_A" in line for line in _argv(calls))


def test_type_text_clears_the_field_before_typing():
    """MOVE_END then backspaces, issued BEFORE the text goes in."""
    ex, calls = _executor()
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    lines = _argv(calls)

    clear_at = next(
        (i for i, line in enumerate(lines)
         if "KEYCODE_MOVE_END" in line and "KEYCODE_DEL" in line),
        None,
    )
    type_at = next(
        (i for i, line in enumerate(lines) if "input text" in line), None,
    )
    assert clear_at is not None, f"no clear sequence issued: {lines}"
    assert type_at is not None, f"nothing was typed: {lines}"
    assert clear_at < type_at, "the field must be cleared before typing"


def test_the_clear_is_a_single_round_trip():
    """
    One `input keyevent` carrying every keycode.

    `input` accepts a list, and a backspace per adb call would cost a round
    trip each - at ~50ms that is seconds per field on a form with several.
    """
    ex, calls = _executor()
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    del_calls = [line for line in _argv(calls) if "KEYCODE_DEL" in line]
    assert len(del_calls) == 1, f"expected one batched clear, got {del_calls}"
    assert del_calls[0].count("KEYCODE_DEL") > 1, "should batch several deletes"


def test_a_known_field_length_bounds_the_delete_count():
    """
    The caller can say how much is in the field, so we do not send 64
    backspaces to clear four digits.
    """
    ex, calls = _executor()
    asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "otp", "existing_length": 4,
        "x": 10, "y": 10,
    }))
    clear = next(line for line in _argv(calls) if "KEYCODE_DEL" in line)
    count = clear.count("KEYCODE_DEL")
    assert 4 <= count <= 24, f"delete count {count} not proportionate to 4 chars"


def test_a_failed_clear_is_surfaced_not_swallowed():
    """
    A clear that did not take means the next type APPENDS.

    It must be visible to the caller, because the field-population verifier is
    what turns that into a retry rather than a silently corrupted form.
    """
    calls: list[tuple[str, ...]] = []

    async def _clear_fails(*args: str):
        calls.append(args)
        if "keyevent" in args and "KEYCODE_DEL" in args:
            return False, "Error: Unknown keycode"
        return True, ""

    ex = ToolExecutor(device_serial="fixture-5554", package_name="com.example.form")
    ex._adb = AsyncMock(side_effect=_clear_fails)

    result = asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    assert result.data.get("field_cleared") is False


def test_a_successful_clear_is_reported():
    ex, _ = _executor()
    result = asyncio.run(ex.execute({
        "tool": "type_text", "field_hint": "email", "x": 10, "y": 10,
    }))
    assert result.data.get("field_cleared") is True
