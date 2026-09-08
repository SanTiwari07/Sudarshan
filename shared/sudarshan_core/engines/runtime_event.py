"""
SUDARSHAN - the canonical representation of one runtime observation.

Why this exists
---------------
Five subsystems each parsed the raw Frida event dict independently:

    goal_tracker          event["data"]["hook"] + event["category"]
    bfci_scorer           event["category"] + timestamps
    workflow_reconstructor  a flattened {hook, category, severity} record
    evidence_store        api / class_name / method / args
    risk_engine           category buckets, plus a separate hook-name allowlist

Five parsers over one wire format is five chances to disagree, and they did.
The agent emits the hook name in BOTH `event["hook"]` and `event["data"]["hook"]`
and the class in BOTH `event["class"]` and `event["data"]["class_name"]`; a
reader that picks the wrong one silently sees "unknown" forever. Worse, each
reader had its own idea of which events describe the SAMPLE and which describe
the harness, so the same event counted as evidence in one place and was filtered
out in another.

This module is the single parse. Everything downstream reads a NormalizedEvent.

The raw event is never destroyed
--------------------------------
`NormalizedEvent.raw` holds the original dict verbatim. Normalization is a VIEW,
not a replacement: a forensic report has to be able to show the bytes the agent
actually sent, and an interpretation the reader cannot check against its source
is not evidence. Everything else on the class is derived and reproducible from
`raw` alone.

Nothing here classifies behaviour or scores anything - see
:mod:`~sudarshan_core.engines.behavior_taxonomy` for the first and
:mod:`~sudarshan_core.engines.bfci_scorer` for the second. This layer only
answers "what did the agent say, and where did it come from".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

logger = logging.getLogger(__name__)

__all__ = [
    "HARNESS_EVENT_CATEGORIES",
    "NormalizedEvent",
    "normalize_event",
    "normalize_events",
    "normalize_collected_events",
]


#: Categories whose events describe the HARNESS, not the sample.
#:
#: Held in one place because every consumer needs the same answer and they used
#: to each have their own. The harness spoofs emulator-identifying Build fields
#: on every run, for benign apps and trojans alike; counting that as sample
#: behaviour marked empty runs conclusive, and counting it as sample EVASION
#: excluded the dynamic axis on five banking trojans and scored them Safe. Both
#: mistakes came from the same missing distinction.
HARNESS_EVENT_CATEGORIES: frozenset = frozenset({"harness_action"})

#: Hook names the harness emits about its own actions. Ten stored runs predate
#: the `harness_action` category and still file these under `anti_analysis`, so
#: the name is checked as well as the bucket.
_HARNESS_HOOKS: frozenset = frozenset({
    "Build.<static fields>",
    "sandbox.build_fields_spoofed",
})


def _first_str(*values: Any) -> str:
    """The first non-empty string among the candidates."""
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if value not in (None, "", [], {}) and not isinstance(value, (dict, list)):
            text = str(value).strip()
            if text:
                return text
    return ""


def _as_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class NormalizedEvent:
    """
    One runtime observation, parsed once.

    Frozen because several subsystems hold the same instance and a mutation in
    one would silently change what another already scored.
    """

    #: The agent's event category, verbatim (`accessibility`, `code_execution`,
    #: `anti_analysis`, ...). Never remapped here - a consumer that wants a
    #: coarser vocabulary derives it, so the original routing stays inspectable.
    category: str = ""
    #: The hook name, e.g. `ProcessBuilder.start`, `WindowManager.addView`.
    hook: str = ""
    #: Java class the hook sits on, when the agent reported one.
    class_name: str = ""
    #: Method half of `hook`, for readers that want it split.
    method: str = ""
    severity: str = "MED"
    #: Milliseconds since epoch, as the agent stamped it. None when unstamped -
    #: distinguished from 0, which would sort to the beginning of the run.
    timestamp_ms: Optional[int] = None
    process: str = ""
    pid: Optional[int] = None
    thread_id: Optional[int] = None
    arguments: Sequence[Any] = ()
    return_value: str = ""
    description: str = ""
    stack_trace: Sequence[str] = ()
    #: The foreground app / activity at the moment the hook fired, when the
    #: agent's runtime context had it. This is what lets a behaviour be
    #: correlated with the screen that produced it.
    foreground_app: str = ""
    current_activity: str = ""
    #: True when this event describes something the HARNESS did.
    harness_attributed: bool = False
    #: The original dict, verbatim and unmodified.
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    # -- Identity ------------------------------------------------------------

    @property
    def qualified_hook(self) -> str:
        """
        `Class.method` where both are known, else whatever we have.

        The agent is inconsistent: some hooks are emitted already qualified
        (`WindowManager.addView`), some as a bare method with the class in a
        separate field (`execve` + `libc`). Matching on the raw name alone
        therefore missed half of them.
        """
        if self.hook and "." in self.hook:
            return self.hook
        if self.class_name and self.method:
            return f"{self.class_name}.{self.method}"
        return self.hook or self.method

    def matches_hook(self, name: str) -> bool:
        """
        Whether this event was produced by the named hook.

        Substring rather than equality, because the agent qualifies some names
        at emit time with a suffix the declaration cannot know in advance -
        `<pkg>.MyService.onAccessibilityEvent` for a subclass it discovered on
        the device. Anchored on a dotted name, so `exec` does not match
        `execve` by accident.
        """
        if not name:
            return False
        target = name.strip()
        for candidate in (self.qualified_hook, self.hook, self.method):
            if not candidate:
                continue
            if candidate == target:
                return True
            if target in candidate and (
                candidate.endswith(target) or f".{target}" in candidate
            ):
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialisable view. `raw` is included so nothing is lost downstream."""
        return {
            "category": self.category,
            "hook": self.hook,
            "qualified_hook": self.qualified_hook,
            "class_name": self.class_name,
            "method": self.method,
            "severity": self.severity,
            "timestamp_ms": self.timestamp_ms,
            "process": self.process,
            "pid": self.pid,
            "thread_id": self.thread_id,
            "description": self.description,
            "foreground_app": self.foreground_app,
            "current_activity": self.current_activity,
            "harness_attributed": self.harness_attributed,
            "raw": dict(self.raw),
        }


def _is_harness(category: str, hook: str, raw: Mapping[str, Any]) -> bool:
    if category in HARNESS_EVENT_CATEGORIES:
        return True
    if hook in _HARNESS_HOOKS:
        return True
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    actor = _first_str(raw.get("actor"), data.get("actor")).lower()
    if actor == "harness":
        return True
    return _first_str(raw.get("category"), data.get("category")).upper() == "HARNESS_ACTION"


def normalize_event(raw: Any, *, category: str = "") -> Optional[NormalizedEvent]:
    """
    Parse one raw agent event. Returns None for anything unparseable.

    `category` is the bucket the event was filed under, supplied by the caller
    when it is iterating a bucketed dict. The event's own `category` field wins
    when present - `_on_message` rewrites the bucket for unregistered categories
    and stashes the original in `original_category`, and the ORIGINAL is what
    the agent meant.
    """
    if not isinstance(raw, dict):
        return None

    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}

    resolved_category = _first_str(
        # The agent's own routing, before _on_message's unregistered-category
        # rewrite. Losing this would merge genuinely new categories into
        # `dangerous_apis` and make them unclassifiable forever.
        raw.get("original_category"),
        raw.get("category"),
        data.get("category"),
        category,
    )

    hook = _first_str(data.get("hook"), raw.get("hook"), raw.get("method"))
    if not hook or hook == "unknown":
        hook = _first_str(raw.get("api"), data.get("api"))

    class_name = _first_str(
        data.get("class_name"), raw.get("class"), raw.get("class_name"),
    )
    method = _first_str(raw.get("method"), data.get("method"))
    if not method:
        # An unqualified hook name IS the method - that is how the agent emits
        # its native hooks (`execve` with `libc` in class_name). Leaving method
        # empty there meant `qualified_hook` could not rebuild `libc.execve`,
        # and every native rule silently failed to match.
        method = hook.rsplit(".", 1)[-1] if "." in hook else hook
    if not class_name and "." in hook:
        class_name = hook.rsplit(".", 1)[0]

    if not hook and not resolved_category:
        return None

    context = raw.get("context") if isinstance(raw.get("context"), dict) else {}
    args = data.get("args") or raw.get("arguments") or ()
    if not isinstance(args, (list, tuple)):
        args = (args,)
    stack = raw.get("stack_trace") or raw.get("stacktrace") or ()
    if not isinstance(stack, (list, tuple)):
        stack = (stack,)

    return NormalizedEvent(
        category=resolved_category,
        hook=hook,
        class_name=class_name,
        method=method,
        severity=_first_str(
            raw.get("severity"), data.get("severity"), "MED",
        ).upper(),
        timestamp_ms=_as_int(
            raw.get("timestamp") if raw.get("timestamp") is not None
            else raw.get("timestamp_ms")
        ),
        process=_first_str(raw.get("process"), raw.get("package"), data.get("package")),
        pid=_as_int(raw.get("pid") if raw.get("pid") is not None else raw.get("process_id")),
        thread_id=_as_int(
            raw.get("thread") if raw.get("thread") is not None else raw.get("thread_id")
        ),
        arguments=tuple(args),
        return_value=_first_str(raw.get("return_value"), data.get("return_value")),
        description=_first_str(
            data.get("description"), raw.get("evidence"), raw.get("description"),
        ),
        stack_trace=tuple(str(s) for s in stack),
        foreground_app=_first_str(context.get("foreground_app")),
        current_activity=_first_str(context.get("current_activity")),
        harness_attributed=_is_harness(resolved_category, hook, raw),
        raw=raw,
    )


def normalize_events(
    events: Iterable[Any], *, category: str = "",
) -> List[NormalizedEvent]:
    """Normalize a flat sequence, dropping anything unparseable."""
    out: List[NormalizedEvent] = []
    for raw in events or ():
        parsed = normalize_event(raw, category=category)
        if parsed is not None:
            out.append(parsed)
    return out


def normalize_collected_events(
    collected: Optional[Mapping[str, Sequence[Any]]],
    *,
    include_harness: bool = False,
) -> List[NormalizedEvent]:
    """
    Normalize `FridaSession.collected_events` - the whole bucketed dict.

    Ordered by timestamp where the agent stamped one, so a consumer that cares
    about causal order (the workflow reconstructor, the goal graph's temporal
    assertions) gets it without re-sorting. Events with no timestamp keep their
    insertion order at the end rather than being sorted to the front, which is
    where a 0 default would have put them.

    Harness events are excluded by default. They are real and they are kept in
    the store, but they describe US - and every historical mistake in this area
    came from a consumer forgetting that.
    """
    out: List[NormalizedEvent] = []
    for bucket, events in (collected or {}).items():
        for parsed in normalize_events(events, category=str(bucket)):
            if parsed.harness_attributed and not include_harness:
                continue
            out.append(parsed)

    stamped = [e for e in out if e.timestamp_ms is not None]
    unstamped = [e for e in out if e.timestamp_ms is None]
    stamped.sort(key=lambda e: e.timestamp_ms or 0)
    return stamped + unstamped
