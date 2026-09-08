"""
The contract between the goal graph and the Frida agent.

There is a hidden coupling in this system: ``goal_tracker._build_default_goals()``
names hook strings, and ``banking_trojan.js`` decides which hook strings exist.
Nothing enforced the join, and it silently broke - 34 of 50 declared triggers
named hooks the agent never emitted, five goals had no reachable trigger at all,
and because stages 3/4/5 all depend on stage 2 (whose only two triggers were
both dead), one ordinary runtime event stalled the whole graph. A measured run
left 11 of 15 goals never attempted while reporting "ALL GOALS COMPLETED OR
SKIPPED" into the planner prompt.

Reconciling the names once fixes today. These tests stop it drifting again.

Two properties are pinned:

  1. Every declared trigger is a hook the agent really emits - checked against
     BOTH the source and the compiled bundle, because the bundle is what runs
     on the device. A hook added to source without ``npm run build`` ships as
     nothing while source-only tests stay green.
  2. Every goal has at least one route to being confirmed. A goal with no route
     is unreachable by construction, and its dependents stall behind it.

The agent vocabulary is PARSED, never hardcoded here. A hardcoded copy would be
a third place to drift.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, Set

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "shared"))

from sudarshan_core.engines.agentic.goal_tracker import (  # noqa: E402
    ConfirmationMode,
    GoalStatus,
    GoalTracker,
)

_HOOKS_DIR = _ROOT / "shared" / "sudarshan_core" / "engines" / "frida_hooks"
AGENT_SOURCE = _HOOKS_DIR / "banking_trojan.js"
AGENT_BUNDLE = _HOOKS_DIR / "banking_trojan.bundle.js"

#: ``hook: 'Name'`` / ``hook: "Name"`` as written in every emit() payload.
_HOOK_RE = re.compile(r"""hook:\s*(['"])([^'"]+)\1""")

#: ``emit('category', { ... hook: 'Name' ... })`` - non-greedy, bounded so a
#: runaway match cannot swallow the next hook.
_EMIT_RE = re.compile(r"""emit\(\s*['"]([a-z_]+)['"]\s*,\s*\{(.{0,800}?)\}\s*\)""", re.S)

#: Hook names the ENGINE synthesises rather than the agent observing an API.
#:
#: Named with a leading verb-phrase that no Android API uses, so they cannot be
#: mistaken in a report for a call the sample made. Each is produced by an
#: explicit device-state read in goal_tracker, not by instrumentation.
ENGINE_SYNTHESISED_HOOKS: frozenset = frozenset({
    # update_from_foreground(): the target package owned the foreground window.
    "foreground_package_confirmed",
    # update_from_permission_state(): dumpsys reported the grant is held.
    "runtime_permission_granted_verified",
})


def _emitted_hook_names(path: Path) -> Set[str]:
    if not path.is_file():
        return set()
    text = path.read_text(encoding="utf-8", errors="replace")
    return {m.group(2) for m in _HOOK_RE.finditer(text)}


def _emitted_by_category(path: Path) -> Dict[str, Set[str]]:
    """category -> hook names emitted under it."""
    out: Dict[str, Set[str]] = {}
    if not path.is_file():
        return out
    text = path.read_text(encoding="utf-8", errors="replace")
    for match in _EMIT_RE.finditer(text):
        hook = _HOOK_RE.search(match.group(2))
        if hook:
            out.setdefault(match.group(1), set()).add(hook.group(2))
    return out


@pytest.fixture(scope="module")
def source_hooks() -> Set[str]:
    hooks = _emitted_hook_names(AGENT_SOURCE)
    assert hooks, (
        f"Parsed no hook names from {AGENT_SOURCE}. Either the file moved or "
        f"the emit() payload shape changed - fix this parser before trusting "
        f"any result below, because an empty vocabulary makes every "
        f"reconciliation test vacuously strict."
    )
    return hooks


@pytest.fixture(scope="module")
def bundle_hooks() -> Set[str]:
    return _emitted_hook_names(AGENT_BUNDLE)


@pytest.fixture()
def tracker() -> GoalTracker:
    return GoalTracker()


def _is_emitted(trigger: str, vocabulary: Set[str]) -> bool:
    """goal_tracker matches with ``trigger in emitted_hook`` - mirror that."""
    return any(trigger in emitted for emitted in vocabulary)


# ── 1. every declared trigger exists in the agent ────────────────────────────

def test_the_agent_source_is_parseable(source_hooks):
    """Guards the parser itself; everything below is meaningless without it."""
    assert len(source_hooks) > 50, (
        f"only {len(source_hooks)} hook names parsed - the agent defines far "
        f"more, so the parser is probably broken"
    )


def test_no_goal_declares_a_hook_the_agent_source_does_not_emit(tracker, source_hooks):
    """The original defect: 34 of 50 declared triggers named nothing real."""
    dead = [
        (g.stage, g.name, h)
        for g in tracker.goals
        for h in g.frida_hooks
        if h not in ENGINE_SYNTHESISED_HOOKS and not _is_emitted(h, source_hooks)
    ]
    assert not dead, (
        "These goals declare completion triggers that banking_trojan.js never "
        "emits, so they can never complete and their dependents stall:\n"
        + "\n".join(f"    [stage {s}] {n}: {h!r}" for s, n, h in dead)
        + "\n\nFix by ONE of:\n"
          "  (a) use the name the agent really emits (check emit(...) payloads);\n"
          "  (b) add the hook to banking_trojan.js AND run `npm run build`;\n"
          "  (c) drop the trigger and record why in a comment.\n"
          "Do NOT substitute a semantically different hook to make a goal "
          "reachable - a goal that fires on the wrong evidence is worse than "
          "one that never fires."
    )


@pytest.mark.skipif(not AGENT_BUNDLE.is_file(), reason="agent bundle not built")
def test_no_goal_declares_a_hook_the_compiled_bundle_does_not_emit(tracker, bundle_hooks):
    """
    The bundle is what actually runs on the device.

    A hook added to the source but never bundled ships as nothing, while every
    source-only check stays green - so this is the check that matters most.
    """
    dead = [
        (g.stage, g.name, h)
        for g in tracker.goals
        for h in g.frida_hooks
        if h not in ENGINE_SYNTHESISED_HOOKS and not _is_emitted(h, bundle_hooks)
    ]
    assert not dead, (
        "These triggers are missing from banking_trojan.bundle.js, which is "
        "the file loaded onto the device:\n"
        + "\n".join(f"    [stage {s}] {n}: {h!r}" for s, n, h in dead)
        + "\n\nIf you just edited the agent, run:\n"
          "    cd shared/sudarshan_core/engines/frida_hooks && npm run build\n"
          "and commit the rebuilt bundle."
    )


@pytest.mark.skipif(not AGENT_BUNDLE.is_file(), reason="agent bundle not built")
def test_the_bundle_is_in_step_with_the_agent_source(source_hooks, bundle_hooks):
    """A stale bundle means unit tests describe code the device never runs."""
    missing = sorted(source_hooks - bundle_hooks)
    assert not missing, (
        f"{len(missing)} hook(s) exist in banking_trojan.js but not in the "
        f"compiled bundle: {missing[:12]}\n"
        f"The bundle is stale. Run `npm run build` in "
        f"shared/sudarshan_core/engines/frida_hooks and commit the result."
    )


def test_completion_categories_are_categories_the_agent_actually_uses(tracker):
    """
    A completion category the agent never emits silently disables the trigger.

    Category gating is what stops `SharedPreferences.getString` under
    `app_telemetry` completing "Login Flow"; a typo in the category name would
    disable the goal instead of narrowing it, and nothing else would notice.
    """
    real = set(_emitted_by_category(AGENT_SOURCE))
    # Engine-synthesised categories are produced by goal_tracker, not the agent.
    real |= {"foreground", "device_state"}
    unknown = [
        (g.stage, g.name, c)
        for g in tracker.goals
        for c in g.completion_categories
        if c not in real
    ]
    assert not unknown, (
        "These goals gate completion on a category the agent never emits, "
        "which disables the trigger entirely:\n"
        + "\n".join(f"    [stage {s}] {n}: {c!r}" for s, n, c in unknown)
        + f"\nCategories the agent really emits: {sorted(real)}"
    )


def test_each_declared_trigger_is_emitted_under_a_category_the_goal_accepts(
    tracker, source_hooks,
):
    """
    Name AND category must line up, or the pair can never match.

    Catches the subtler half of the drift: a trigger whose name is real and
    whose category is real, but which the agent never emits in that COMBINATION
    - e.g. gating `Cipher.doFinal` on `banking` when the agent only ever sends
    it to `app_telemetry`.
    """
    by_cat = _emitted_by_category(AGENT_SOURCE)
    unreachable = []
    for goal in tracker.goals:
        if goal.confirmation is not ConfirmationMode.FRIDA_HOOK:
            continue
        for trigger in goal.frida_hooks:
            if trigger in ENGINE_SYNTHESISED_HOOKS:
                continue
            ok = any(
                goal.accepts_completion_category(cat) and _is_emitted(trigger, hooks)
                for cat, hooks in by_cat.items()
            )
            if not ok:
                unreachable.append((goal.stage, goal.name, trigger,
                                    list(goal.completion_categories)))
    assert not unreachable, (
        "These triggers exist and these categories exist, but the agent never "
        "emits that name UNDER that category, so the pair can never match:\n"
        + "\n".join(
            f"    [stage {s}] {n}: {h!r} gated on {c}"
            for s, n, h, c in unreachable
        )
    )


# ── 2. every goal is reachable ───────────────────────────────────────────────

def test_every_goal_declares_how_it_can_be_confirmed(tracker):
    """A goal with no confirmation route is unreachable by construction."""
    for goal in tracker.goals:
        assert isinstance(goal.confirmation, ConfirmationMode), (
            f"[stage {goal.stage}] {goal.name} has no confirmation mode"
        )


def test_no_goal_has_zero_completion_triggers(tracker, source_hooks):
    """
    Every goal must have a real route to COMPLETED.

    Five goals had none - stages 2, 11, 12, 13 and 15 - and stage 2 blocked
    stages 3, 4 and 5 behind it.
    """
    stranded = []
    for goal in tracker.goals:
        if goal.confirmation is ConfirmationMode.UNSUPPORTED:
            continue    # covered by the test below
        if goal.confirmation is ConfirmationMode.DEVICE_STATE:
            continue    # confirmed by an observation, not a hook
        if goal.confirmation is ConfirmationMode.BEHAVIOR:
            # Confirmed by a canonical behaviour, which maps several hooks onto
            # one meaning and therefore survives a rename. NOT an exemption from
            # the guard - the goal must still declare a real route, and the
            # behaviour names are themselves checked against the agent source by
            # test_behavior_taxonomy.test_every_declared_hook_is_emitted_by_the_agent.
            if not goal.required_behaviors:
                stranded.append((goal.stage, goal.name))
            continue
        live = [h for h in goal.frida_hooks if _is_emitted(h, source_hooks)]
        if not live:
            stranded.append((goal.stage, goal.name))
    assert not stranded, (
        "These goals can never reach COMPLETED - no declared trigger is "
        "emitted by the agent:\n"
        + "\n".join(f"    [stage {s}] {n}" for s, n in stranded)
        + "\nGive the goal a real trigger, confirm it from device state, or "
          "declare it UNSUPPORTED with a reason."
    )


def test_an_unsupported_goal_must_say_why_and_carry_no_dead_triggers(tracker):
    """
    UNSUPPORTED is a claim about the ENGINE, and it has to be justified.

    It must never be a quiet dumping ground for goals somebody could not make
    work: the reason is carried into the report by audit_unfulfilled_goals().
    """
    for goal in tracker.goals:
        if goal.confirmation is not ConfirmationMode.UNSUPPORTED:
            continue
        assert goal.unsupported_reason.strip(), (
            f"[stage {goal.stage}] {goal.name} is UNSUPPORTED without a stated "
            f"reason. Say which instrument is missing and why it was not added."
        )
        assert not goal.frida_hooks, (
            f"[stage {goal.stage}] {goal.name} is UNSUPPORTED but still "
            f"declares triggers {goal.frida_hooks} - remove them, or the goal "
            f"is not really unsupported."
        )


def test_a_device_state_goal_declares_no_hook(tracker):
    """Mixed modes hide which observation actually confirmed the goal."""
    for goal in tracker.goals:
        if goal.confirmation is not ConfirmationMode.DEVICE_STATE:
            continue
        assert not goal.frida_hooks, (
            f"[stage {goal.stage}] {goal.name} is confirmed by device state "
            f"but also declares hooks {goal.frida_hooks}"
        )


def test_unsupported_goals_are_resolved_not_left_pending(tracker):
    """
    The stall itself: an unconfirmable goal must not block its dependents.

    Resolution happens in the constructor, so the gap is visible in the first
    status dump rather than discovered when the run has already been wasted.
    """
    for goal in tracker.goals:
        if goal.confirmation is ConfirmationMode.UNSUPPORTED:
            assert goal.status is GoalStatus.UNSUPPORTED, (
                f"[stage {goal.stage}] {goal.name} declares no instrument but "
                f"is {goal.status.value}; it will hold its dependents PENDING"
            )


def test_every_dependency_names_a_goal_that_exists(tracker):
    """A dependency on a missing stage can never resolve."""
    stages = {g.stage for g in tracker.goals}
    for goal in tracker.goals:
        missing = [d for d in goal.depends_on if d not in stages]
        assert not missing, (
            f"[stage {goal.stage}] {goal.name} depends on non-existent "
            f"stage(s) {missing}"
        )


def test_the_dependency_graph_is_acyclic_and_forward_only(tracker):
    """A backward edge is a deadlock nobody would find at runtime."""
    for goal in tracker.goals:
        backward = [d for d in goal.depends_on if d >= goal.stage]
        assert not backward, (
            f"[stage {goal.stage}] {goal.name} depends on stage(s) {backward} "
            f"at or after itself - the graph must run forward only"
        )


# ── 3. the guards themselves ─────────────────────────────────────────────────
#
# A contract test that cannot fail is worse than no test: it reports the
# contract is intact whatever happens to it. These re-break the contract
# deliberately, one way at a time, and assert the matching guard notices.

_ALL_GUARDS = (
    ("declares-dead-hook",
     lambda t, src: test_no_goal_declares_a_hook_the_agent_source_does_not_emit(t, src)),
    ("zero-triggers",
     lambda t, src: test_no_goal_has_zero_completion_triggers(t, src)),
    ("unknown-completion-category",
     lambda t, src: test_completion_categories_are_categories_the_agent_actually_uses(t)),
    ("name-category-mismatch",
     lambda t, src: test_each_declared_trigger_is_emitted_under_a_category_the_goal_accepts(t, src)),
    ("unsupported-left-pending",
     lambda t, src: test_unsupported_goals_are_resolved_not_left_pending(t)),
    ("unsupported-without-reason",
     lambda t, src: test_an_unsupported_goal_must_say_why_and_carry_no_dead_triggers(t)),
    ("backward-edge",
     lambda t, src: test_the_dependency_graph_is_acyclic_and_forward_only(t)),
)


def _some_guard_rejects(tracker: GoalTracker, source_hooks: Set[str]) -> str:
    """Name of the first guard that rejects this tracker, or "" if none do."""
    for name, guard in _ALL_GUARDS:
        try:
            guard(tracker, source_hooks)
        except AssertionError:
            return name
    return ""


@pytest.mark.parametrize("label, break_it", [
    # The exact drift that caused the stall: a trigger naming nothing real.
    ("a dead hook name is reintroduced",
     lambda t: t.get_goal(6).frida_hooks.append("BroadcastReceiver.onReceive")),
    # A goal quietly stripped of every way to complete.
    ("a goal loses all its triggers",
     lambda t: t.get_goal(6).frida_hooks.clear()),
    # A typo in a category disables the trigger instead of narrowing it.
    ("a completion category is misspelled",
     lambda t: t.get_goal(5).completion_categories.__setitem__(0, "bankng")),
    # Real name, real category, combination the agent never emits.
    ("a real hook is gated on a category it never fires under",
     lambda t: (t.get_goal(10).frida_hooks.clear(),
                t.get_goal(10).frida_hooks.append("Cipher.doFinal"))),
    # The stall itself.
    ("an unsupported goal is left PENDING",
     lambda t: setattr(t.get_goal(11), "status", GoalStatus.PENDING)),
    # UNSUPPORTED used as a silent dumping ground.
    ("an unsupported goal stops explaining itself",
     lambda t: setattr(t.get_goal(11), "unsupported_reason", "")),
    ("a backward dependency edge is added",
     lambda t: t.get_goal(4).depends_on.append(9)),
])
def test_the_contract_guards_actually_catch_a_broken_contract(
    label, break_it, source_hooks,
):
    """Each guard is shown to reject the breakage it exists to catch."""
    broken = GoalTracker()
    break_it(broken)
    caught = _some_guard_rejects(broken, source_hooks)
    assert caught, (
        f"No guard rejected a tracker where {label}. The contract tests would "
        f"pass through this regression silently, which is the failure mode "
        f"they exist to prevent."
    )


def test_the_guards_accept_the_real_goal_graph(tracker, source_hooks):
    """Complements the above: the guards are not simply rejecting everything."""
    assert _some_guard_rejects(tracker, source_hooks) == "", (
        "A guard rejects the shipped goal graph - the contract is broken now, "
        "not hypothetically."
    )
