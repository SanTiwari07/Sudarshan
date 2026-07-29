"""
SUDARSHAN — Screen Graph Builder
=================================
Maintains spatial graph memory of UI screens (nodes) and navigational actions (edges).
Calculates screen identity hashes based on activity name and normalized element topology.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from sudarshan_core.engines.agentic.screen_classifier import classify_screen

logger = logging.getLogger(__name__)


@dataclass
class ScreenNode:
    """A node representing a unique UI screen in the Screen Graph."""
    screen_hash: str
    activity_name: str
    package_name: str
    semantic_type: str
    visit_count: int = 1
    first_visit_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    last_visit_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    unexplored_actions: List[Dict[str, Any]] = field(default_factory=list)
    actionable_node_count: int = 0


@dataclass
class ScreenEdge:
    """A directed edge representing navigation between two screens."""
    source_hash: str
    target_hash: str
    action_type: str        # click / input / scroll / back / launch
    action_target: str      # element node_id or label
    timestamp_ms: int = field(default_factory=lambda: int(time.time() * 1000))


def compute_screen_hash(activity_name: str, ui_nodes: List[Any]) -> str:
    """
    Compute a stable SHA-256 hash for a screen based on activity and normalized UI elements.
    Independent of raw pixel coordinates.
    """
    parts = [activity_name]
    for n in ui_nodes:
        cls_name = getattr(n, "class_name", "") or (n.get("class_name") if isinstance(n, dict) else "")
        text = getattr(n, "text", "") or (n.get("text") if isinstance(n, dict) else "")
        desc = getattr(n, "desc", "") or (n.get("desc") if isinstance(n, dict) else "")
        res_id = getattr(n, "resource_id", "") or (n.get("resource_id") if isinstance(n, dict) else "")
        parts.append(f"{cls_name}|{text[:20]}|{desc[:20]}|{res_id}")

    raw = ";".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class ScreenGraphBuilder:
    """
    Maintains the Screen Graph memory structure and detects navigation cycles.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, ScreenNode] = {}
        self._edges: List[ScreenEdge] = []
        self._history: List[str] = []  # Chronological list of screen hashes
        self._lock = threading.Lock()

    def process_observation(
        self,
        activity_name: str,
        package_name: str,
        ui_nodes: List[Any],
        raw_xml: str = ""
    ) -> ScreenNode:
        """
        Incorporate observation into the screen graph. Returns the resulting ScreenNode.
        """
        shash = compute_screen_hash(activity_name, ui_nodes)
        now_ms = int(time.time() * 1000)

        with self._lock:
            if shash in self._nodes:
                node = self._nodes[shash]
                node.visit_count += 1
                node.last_visit_ms = now_ms
            else:
                classification = classify_screen(activity_name, ui_nodes, raw_xml, package_name)
                
                unexplored = []
                for idx, n in enumerate(ui_nodes):
                    nid = getattr(n, "node_id", f"n{idx}")
                    lbl = getattr(n, "text", "") or getattr(n, "desc", "") or getattr(n, "class_name", "")
                    unexplored.append({"node_id": nid, "label": str(lbl)})

                node = ScreenNode(
                    screen_hash=shash,
                    activity_name=activity_name,
                    package_name=package_name,
                    semantic_type=classification.screen_type,
                    visit_count=1,
                    first_visit_ms=now_ms,
                    last_visit_ms=now_ms,
                    unexplored_actions=unexplored,
                    actionable_node_count=len(ui_nodes),
                )
                self._nodes[shash] = node

            self._history.append(shash)
            return node

    def record_action(
        self,
        source_hash: str,
        target_hash: str,
        action_type: str,
        action_target: str
    ) -> None:
        """Record a navigation edge between two screens."""
        with self._lock:
            edge = ScreenEdge(
                source_hash=source_hash,
                target_hash=target_hash,
                action_type=action_type,
                action_target=action_target,
            )
            self._edges.append(edge)

    def is_loop_detected(self, current_hash: str, max_visits: int = 3, window: int = 5) -> bool:
        """
        Detect if current_hash has been visited > max_visits times within the last `window` steps.
        """
        with self._lock:
            recent = self._history[-window:] if len(self._history) >= window else self._history
            return recent.count(current_hash) >= max_visits

    def get_nodes(self) -> List[ScreenNode]:
        with self._lock:
            return list(self._nodes.values())

    def get_edges(self) -> List[ScreenEdge]:
        with self._lock:
            return list(self._edges)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "nodes": [asdict(n) for n in self._nodes.values()],
                "edges": [asdict(e) for e in self._edges],
                "total_unique_screens": len(self._nodes),
                "total_navigation_edges": len(self._edges),
            }

    def to_mermaid(self) -> str:
        """Render Screen Graph as Mermaid diagram."""
        with self._lock:
            if not self._nodes:
                return "graph TD\n  Empty[No screens visited]"
            lines = ["graph TD"]
            for node in self._nodes.values():
                short_hash = node.screen_hash[:6]
                act_short = node.activity_name.split(".")[-1]
                lines.append(f'  {short_hash}["{act_short} ({node.semantic_type}) v:{node.visit_count}"]')
            for edge in self._edges:
                src = edge.source_hash[:6]
                tgt = edge.target_hash[:6]
                lines.append(f'  {src} -->|{edge.action_type}:{edge.action_target[:15]}| {tgt}')
            return "\n".join(lines)
