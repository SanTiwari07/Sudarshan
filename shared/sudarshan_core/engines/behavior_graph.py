"""
SUDARSHAN — Runtime Behavior Graph Infrastructure
===================================================
Subscribes to RuntimeEventBus events (UI_ACTION, NETWORK_EVENT, FRIDA_EVENT, THREAT_DETECTED)
and constructs a causal Directed Acyclic Graph (DAG) representing attack progression.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.event_bus import EventType, RuntimeEventBus

logger = logging.getLogger(__name__)


@dataclass
class BehaviorNode:
    """A node in the malware execution behavior graph."""
    node_id: str          # e.g., NODE-001
    label: str            # e.g., "Accessibility Service Enabled"
    event_type: str       # UI_ACTION / FRIDA_EVENT / NETWORK_EVENT / THREAT_DETECTED
    evidence_id: str      # EVID-NNN reference
    timestamp_ms: int     # Unix ms
    category: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorEdge:
    """A directed edge connecting two behavior nodes."""
    source_id: str        # NODE-001
    target_id: str        # NODE-002
    relation: str         # "TRIGGERS" / "LEADS_TO" / "EXFILTRATES_TO"


class BehaviorGraphBuilder:
    """
    Subscribes to RuntimeEventBus and dynamically constructs the attack behavior DAG.
    """

    def __init__(self, event_bus: Optional[RuntimeEventBus] = None) -> None:
        self._nodes: List[BehaviorNode] = []
        self._edges: List[BehaviorEdge] = []
        self._lock = threading.Lock()
        self._counter = 0

        if event_bus is not None:
            event_bus.subscribe(self._on_event)
            logger.debug("[BehaviorGraph] Subscribed to RuntimeEventBus")

    def _next_node_id(self) -> str:
        self._counter += 1
        return f"NODE-{self._counter:03d}"

    def _on_event(self, event: Dict[str, Any]) -> None:
        """Process incoming events and append to behavior DAG."""
        etype = event.get("event_type", event.get("type", ""))
        payload = event.get("payload", event.get("data", {}))
        
        # Only build graph for meaningful security/UI/network events
        # Agent hook payloads use FRIDA_HOOK until normalized at publish time;
        # accept both for backward compatibility with raw dict publishes.
        if etype == "FRIDA_HOOK":
            etype = EventType.FRIDA_EVENT

        if etype not in (
            EventType.UI_ACTION,
            EventType.NETWORK_EVENT,
            EventType.FRIDA_EVENT,
            EventType.THREAT_DETECTED,
            EventType.SCREENSHOT_CAPTURED,
        ):
            return

        ts_ms = int(event.get("timestamp", time.time()) * 1000)
        ev_id = payload.get("evidence_id", payload.get("finding_id", ""))
        
        label = (
            payload.get("description")
            or payload.get("label")
            or payload.get("hook")
            or payload.get("url")
            or f"Event {etype}"
        )

        with self._lock:
            prev_node_id = self._nodes[-1].node_id if self._nodes else None
            node_id = self._next_node_id()

            node = BehaviorNode(
                node_id=node_id,
                label=str(label)[:80],
                event_type=etype,
                evidence_id=ev_id,
                timestamp_ms=ts_ms,
                category=event.get("category", ""),
                details=payload if isinstance(payload, dict) else {},
            )
            self._nodes.append(node)

            if prev_node_id:
                relation = "LEADS_TO"
                if etype == EventType.NETWORK_EVENT:
                    relation = "EXFILTRATES_TO"
                elif etype == EventType.THREAT_DETECTED:
                    relation = "CORRELATES_WITH"
                self._edges.append(BehaviorEdge(source_id=prev_node_id, target_id=node_id, relation=relation))

    def add_node(self, label: str, event_type: str, evidence_id: str = "", details: Optional[Dict] = None) -> str:
        """Manually insert a node into the behavior graph."""
        with self._lock:
            prev_node_id = self._nodes[-1].node_id if self._nodes else None
            node_id = self._next_node_id()
            node = BehaviorNode(
                node_id=node_id,
                label=label,
                event_type=event_type,
                evidence_id=evidence_id,
                timestamp_ms=int(time.time() * 1000),
                details=details or {},
            )
            self._nodes.append(node)
            if prev_node_id:
                self._edges.append(BehaviorEdge(source_id=prev_node_id, target_id=node_id, relation="LEADS_TO"))
            return node_id

    def get_nodes(self) -> List[BehaviorNode]:
        with self._lock:
            return list(self._nodes)

    def get_edges(self) -> List[BehaviorEdge]:
        with self._lock:
            return list(self._edges)

    def to_dict(self) -> Dict[str, Any]:
        """Return dict summary of behavior DAG."""
        with self._lock:
            return {
                "nodes": [asdict(n) for n in self._nodes],
                "edges": [asdict(e) for e in self._edges],
                "node_count": len(self._nodes),
                "edge_count": len(self._edges),
            }

    def to_mermaid(self) -> str:
        """Generate Mermaid flowchart markdown string."""
        with self._lock:
            if not self._nodes:
                return "flowchart TD\n  Empty[No behavior events captured]"
            lines = ["flowchart TD"]
            for n in self._nodes:
                safe_label = n.label.replace('"', "'")
                lines.append(f'  {n.node_id}["{n.node_id}: {safe_label}"]')
            for e in self._edges:
                lines.append(f'  {e.source_id} -->|{e.relation}| {e.target_id}')
            return "\n".join(lines)

    def flush(self, output_path: Path) -> int:
        """Persist behavior graph JSON to disk."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
            logger.info("[BehaviorGraph] Flushed %d nodes -> %s", len(self._nodes), output_path)
        except Exception as e:
            logger.error("[BehaviorGraph] Failed to flush behavior graph: %s", e)
        return len(self._nodes)
