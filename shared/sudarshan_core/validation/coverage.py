"""Coverage metrics derived from dynamic analysis artifacts."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class CoverageMetrics:
    activities_discovered: int = 0
    activities_visited: int = 0
    fragments_visited: int = 0
    permission_dialogs_found: int = 0
    permission_dialogs_handled: int = 0
    unique_screens: int = 0
    explorer_depth: int = 0
    runtime_apis_hooked: int = 0
    accessibility_callbacks: int = 0
    network_requests: int = 0
    security_events: int = 0
    coverage_percent: float = 0.0
    hook_fire_total: int = 0
    raw_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "activities_discovered": self.activities_discovered,
            "activities_visited": self.activities_visited,
            "fragments_visited": self.fragments_visited,
            "permission_dialogs_found": self.permission_dialogs_found,
            "permission_dialogs_handled": self.permission_dialogs_handled,
            "unique_screens": self.unique_screens,
            "explorer_depth": self.explorer_depth,
            "runtime_apis_hooked": self.runtime_apis_hooked,
            "accessibility_callbacks": self.accessibility_callbacks,
            "network_requests": self.network_requests,
            "security_events": self.security_events,
            "coverage_percent": round(self.coverage_percent, 2),
            "hook_fire_total": self.hook_fire_total,
        }


def compute_coverage(dynamic_result: Dict[str, Any], artifact_dir: Path) -> CoverageMetrics:
    m = CoverageMetrics()
    cov = dynamic_result.get("coverage_metrics") or {}
    m.unique_screens = int(cov.get("unique_screens_visited") or cov.get("screens") or 0)
    m.explorer_depth = int(cov.get("navigation_depth") or 0)
    m.permission_dialogs_handled = int(cov.get("permissions_granted") or 0)
    m.coverage_percent = float(cov.get("exploration_coverage_percent") or cov.get("coverage_percent") or 0)

    activities = dynamic_result.get("activities_triggered") or []
    m.activities_visited = len(activities)

    sg_path = artifact_dir / "screen_graph.json"
    if sg_path.is_file():
        try:
            sg = json.loads(sg_path.read_text(encoding="utf-8"))
            m.activities_discovered = int(sg.get("total_unique_screens") or len(sg.get("nodes", [])))
            m.raw_details["screen_graph"] = True
        except Exception:
            pass

    perms_path = artifact_dir / "permissions.json"
    if perms_path.is_file():
        try:
            pj = json.loads(perms_path.read_text(encoding="utf-8"))
            m.permission_dialogs_found = len(pj.get("events", pj.get("granted", [])))
        except Exception:
            pass

    raw_counts = dynamic_result.get("raw_event_counts") or {}
    m.accessibility_callbacks = int(raw_counts.get("accessibility", 0))
    m.network_requests = int(raw_counts.get("network", 0))
    m.security_events = int(raw_counts.get("anti_analysis", 0)) + int(
        raw_counts.get("overlay", 0)
    )
    hook_fires = dynamic_result.get("hook_fire_counts") or {}
    m.hook_fire_total = sum(int(v) for v in hook_fires.values())
    m.runtime_apis_hooked = len(dynamic_result.get("api_calls") or [])

    if m.coverage_percent == 0 and m.unique_screens > 0:
        m.coverage_percent = min(100.0, m.unique_screens * 10.0)

    m.raw_details["raw_event_counts"] = raw_counts
    return m
