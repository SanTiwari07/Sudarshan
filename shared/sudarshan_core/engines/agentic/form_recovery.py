"""
SUDARSHAN - Form stagnation recovery
====================================
Get the walk off a form it has stopped being able to move.

The failure this exists for is specific and was reproducible on every
login-gated sample in the corpus. The agent types into the password box; the
soft keyboard comes up and covers the bottom of the screen; the "Login" button
is under it. Every subsequent tap lands on a keyboard key, so the screen hash
does not change, so the action verifier reports "unchanged", so the retry ladder
re-dispatches the same tap, and the run ends with three identical screenshots of
one form and a report saying the app never left its login screen.

None of the loop's existing recovery paths help there. Backtracking presses
BACK, which leaves the form. Scrolling moves a page that is not scrollable.
Re-planning re-derives the same action, because the action was never wrong - it
was aimed at a control that something was standing in front of.

So this module supplies the four things worth trying, in the order a person
would try them, and remembers which have been tried on which screen so a stuck
form cannot absorb the budget re-trying the same escape:

  1. Put the keyboard away, so the controls under it become tappable again.
  2. Press the keyboard's own action key, which commits a completed form
     whatever the layout below it looks like.
  3. Tap the submit control directly at the coordinates the observation gave
     us - deliberately including one already marked resolved, because "tried
     and nothing happened" is the symptom being treated.
  4. Scroll a little, in case the button is genuinely below the fold.

The ladder is per-screen and each rung is spent once. When it is exhausted the
caller gets None back and falls through to ordinary selection, so this can delay
the normal walk by at most four actions and can never replace it.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)

#: Consecutive actions that changed nothing on screen before recovery engages.
#: Two, not one: a single unchanged screen is normal - typing into a field is
#: supposed to leave the hash where it was - and reacting to it would fire the
#: ladder on every well-behaved form.
STAGNATION_THRESHOLD: int = max(1, int(
    os.getenv("SUDARSHAN_FORM_STAGNATION_THRESHOLD", "2")
))

#: How far to scroll when trying to bring a covered CTA into view. Small on
#: purpose: the goal is to reveal the button under the fold, not to leave the
#: part of the form that has already been filled.
REVEAL_SCROLL_AMOUNT: int = int(
    os.getenv("SUDARSHAN_FORM_REVEAL_SCROLL", "400")
)

STEP_HIDE_KEYBOARD: str = "hide_keyboard"
STEP_PRESS_ENTER: str = "press_enter"
STEP_TAP_SUBMIT: str = "tap_submit"
STEP_SCROLL_REVEAL: str = "scroll_reveal"

#: The ladder, in the order it is climbed.
RECOVERY_STEPS: Tuple[str, ...] = (
    STEP_HIDE_KEYBOARD,
    STEP_PRESS_ENTER,
    STEP_TAP_SUBMIT,
    STEP_SCROLL_REVEAL,
)

#: Marks an action as coming from here, so the loop can let it past the stage
#: allowlist the same way it lets exploration-graph actions past.
SOURCE: str = "form_recovery"


@dataclass
class SubmitTarget:
    """The control that commits the form, as the last observation saw it."""
    label: str = ""
    x: int = 0
    y: int = 0
    bounds: str = ""
    action_id: str = ""

    @property
    def usable(self) -> bool:
        return bool(self.label and (self.x or self.y))


@dataclass
class FormScreen:
    """What recovery needs to know about the screen it is stuck on."""
    state_id: str = ""
    screen_type: str = ""
    input_count: int = 0
    unfilled_input_count: int = 0
    submit: Optional[SubmitTarget] = None
    keyboard_visible: Optional[bool] = None

    @property
    def is_form(self) -> bool:
        return self.input_count > 0

    @property
    def all_inputs_filled(self) -> bool:
        return self.input_count > 0 and self.unfilled_input_count == 0


def describe_form_screen(state: Any, screen_type: str = "") -> FormScreen:
    """
    Read a form's completion state off an ExplorationState.

    Tolerant of anything action-item shaped, so a caller holding a different
    inventory (a planner's own view, a test double) can use it too. A missing
    attribute means "not stated" and never raises.
    """
    from sudarshan_core.engines.agentic.exploration_engine import (
        _is_form_commit_action,
    )

    items: Sequence[Any] = list(getattr(state, "actionable_elements", None) or [])
    inputs = [a for a in items if getattr(a, "action_type", "") == "input"]
    unfilled = [a for a in inputs if not getattr(a, "resolved", False)]

    submit: Optional[SubmitTarget] = None
    for item in items:
        try:
            if not _is_form_commit_action(item):
                continue
        except Exception:  # pragma: no cover - a predicate must not block recovery
            continue
        candidate = SubmitTarget(
            label=str(getattr(item, "label", "") or ""),
            x=int(getattr(item, "center_x", 0) or 0),
            y=int(getattr(item, "center_y", 0) or 0),
            bounds=str(getattr(item, "bounds", "") or ""),
            action_id=str(getattr(item, "action_id", "") or ""),
        )
        if candidate.usable:
            submit = candidate
            break

    return FormScreen(
        state_id=str(getattr(state, "state_id", "") or ""),
        screen_type=str(screen_type or getattr(state, "semantic_type", "") or ""),
        input_count=len(inputs),
        unfilled_input_count=len(unfilled),
        submit=submit,
    )


class FormRecoveryLadder:
    """Per-screen escalation, one rung per screen per run."""

    def __init__(self) -> None:
        self._spent: Dict[str, Set[str]] = {}

    def spent_steps(self, state_id: str) -> Set[str]:
        return set(self._spent.get(state_id, set()))

    def reset(self, state_id: str) -> None:
        """Forget this screen's history - it moved, so the ladder starts over."""
        self._spent.pop(state_id, None)

    def _applicable(self, step: str, form: FormScreen) -> bool:
        if step == STEP_HIDE_KEYBOARD:
            # Only when the IME is CONFIRMED up. `None` is an unreadable probe,
            # and hiding a keyboard that is not there sends BACK out of the app.
            return form.keyboard_visible is True
        if step == STEP_PRESS_ENTER:
            # The action key commits a form; sending it to a half-filled one
            # asks the app to validate incomplete input and reads back as a
            # refusal.
            return form.all_inputs_filled
        if step == STEP_TAP_SUBMIT:
            # Same guard as STEP_PRESS_ENTER above, for the same reason: both
            # commit the form. Enter was guarded and the submit TAP was not,
            # which is the inconsistency this closes.
            #
            # Measured on the Anubis payload's four-field form: two fields were
            # filled and verified, stagnation fired anyway (populating a WebView
            # input does not change the screen hash), recovery climbed to
            # tap_submit and committed the form with Mother Name and Date Of
            # Birth still empty. The app validated, refused, and the walk read
            # that refusal as the app rejecting our data rather than as us
            # submitting half a form.
            return (
                form.all_inputs_filled
                and form.submit is not None
                and form.submit.usable
            )
        if step == STEP_SCROLL_REVEAL:
            return True
        return False

    def next_step(self, form: FormScreen) -> Optional[str]:
        if not form.state_id or not form.is_form:
            return None
        spent = self._spent.setdefault(form.state_id, set())
        for step in RECOVERY_STEPS:
            if step in spent:
                continue
            if not self._applicable(step, form):
                continue
            return step
        return None

    def plan(self, form: FormScreen) -> Optional[Dict[str, Any]]:
        """
        The next thing to try on this stuck form, as an executable action.

        Returns None when the ladder is exhausted or the screen is not a form,
        and the caller then proceeds with ordinary action selection.
        """
        step = self.next_step(form)
        if step is None:
            return None
        self._spent.setdefault(form.state_id, set()).add(step)
        action = _build_action(step, form)
        if action is None:
            return None
        logger.info(
            "[FormRecovery] state=%s step=%s inputs=%d unfilled=%d "
            "keyboard=%s submit=%s",
            form.state_id, step, form.input_count, form.unfilled_input_count,
            form.keyboard_visible,
            form.submit.label if form.submit else "none",
        )
        return action


def _build_action(step: str, form: FormScreen) -> Optional[Dict[str, Any]]:
    base: Dict[str, Any] = {
        "goal": "DEEP_EXPLORATION",
        "confidence": 0.8,
        "_source": SOURCE,
        "_selected_by": SOURCE,
        "_recovery_step": step,
        "_state_id": form.state_id,
    }

    if step == STEP_HIDE_KEYBOARD:
        base.update({
            "tool": "hide_keyboard",
            # A description, not a target. The loop derives its audit label and
            # its loop-detection key from `text`, and leaving it empty would let
            # record_action match this against any inventory item that also has
            # no caption.
            "text": "dismiss soft keyboard",
            "reasoning": (
                f"Form on {form.state_id} has not moved and the software "
                f"keyboard is covering it - dismissing it so the remaining "
                f"controls become tappable"
            ),
        })
        return base

    if step == STEP_PRESS_ENTER:
        base.update({
            "tool": "press_enter",
            "key": "enter",
            "text": "keyboard action key",
            "reasoning": (
                f"All {form.input_count} field(s) on {form.state_id} are "
                f"filled and the screen has not moved - committing through the "
                f"keyboard's action key"
            ),
        })
        return base

    if step == STEP_TAP_SUBMIT:
        if form.submit is None or not form.submit.usable:
            return None
        base.update({
            "tool": "click_text",
            "text": form.submit.label,
            "x": form.submit.x,
            "y": form.submit.y,
            "_bounds": form.submit.bounds,
            "_action_id": form.submit.action_id,
            # Coordinates came from the observation of this very screen, so
            # there is nothing for an XML lookup to rediscover.
            "_geometry_trusted": bool(form.submit.bounds),
            "_executable_type": "TAP",
            "reasoning": (
                f"Form on {form.state_id} is filled but has not advanced - "
                f"tapping '{form.submit.label}' directly at its observed "
                f"coordinates"
            ),
        })
        return base

    if step == STEP_SCROLL_REVEAL:
        base.update({
            "tool": "scroll",
            "direction": "down",
            "amount": REVEAL_SCROLL_AMOUNT,
            "text": "reveal covered controls",
            "reasoning": (
                f"Form on {form.state_id} has not advanced - scrolling to "
                f"bring a covered submit control into view"
            ),
        })
        return base

    return None
