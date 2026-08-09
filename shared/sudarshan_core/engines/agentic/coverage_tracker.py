"""
SUDARSHAN - Exploration Coverage Metrics Suite
===============================================
Calculates research-grade metrics on dynamic UI exploration coverage:
  - Unique screens discovered & visited
  - Exploration coverage percentage
  - Actionable UI nodes interacted with
  - Permissions prompted vs auto-granted
  - Navigation depth & loop counts
"""

from __future__ import annotations

import logging
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CoverageMetrics:
    total_screens_discovered: int = 0
    unique_screens_visited: int = 0
    exploration_coverage_percent: float = 0.0
    total_actionable_nodes_found: int = 0
    nodes_interacted: int = 0
    executed_actions_count: int = 0
    failed_actions_count: int = 0
    loops_detected_and_broken: int = 0
    permissions_prompted: int = 0
    permissions_granted: int = 0
    dialogs_dismissed: int = 0
    exploration_depth: int = 0


class CoverageTracker:
    """
    Maintains and calculates formal dynamic exploration metrics.
    """

    def __init__(self) -> None:
        self._metrics = CoverageMetrics()
        self._interacted_nodes: set = set()
        self._lock = threading.Lock()

    def update_screens(self, discovered_count: int, visited_count: int) -> None:
        with self._lock:
            self._metrics.total_screens_discovered = discovered_count
            self._metrics.unique_screens_visited = visited_count
            if discovered_count > 0:
                self._metrics.exploration_coverage_percent = round((visited_count / discovered_count) * 100.0, 1)

    def record_node_found(self, count: int) -> None:
        with self._lock:
            self._metrics.total_actionable_nodes_found += count

    def record_action_executed(self, node_id: str, success: bool = True) -> None:
        with self._lock:
            self._metrics.executed_actions_count += 1
            if node_id:
                self._interacted_nodes.add(node_id)
                self._metrics.nodes_interacted = len(self._interacted_nodes)
            if not success:
                self._metrics.failed_actions_count += 1

    def record_loop_broken(self) -> None:
        with self._lock:
            self._metrics.loops_detected_and_broken += 1

    def record_permission(self, granted: bool = True) -> None:
        with self._lock:
            self._metrics.permissions_prompted += 1
            if granted:
                self._metrics.permissions_granted += 1

    def update_depth(self, depth: int) -> None:
        with self._lock:
            if depth > self._metrics.exploration_depth:
                self._metrics.exploration_depth = depth

    def get_summary(self) -> Dict[str, Any]:
        with self._lock:
            return asdict(self._metrics)
