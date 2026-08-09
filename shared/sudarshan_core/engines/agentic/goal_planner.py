"""
SUDARSHAN - Goal Hierarchy & Planner Goals
============================================
Defines explicit goal classes for autonomous investigation:
  - GOAL_GRANT_PERMISSIONS
  - GOAL_TRIGGER_ACCESSIBILITY
  - GOAL_TRIGGER_OVERLAY
  - GOAL_TRIGGER_BANKING_FLOW
  - GOAL_TRIGGER_LOGIN
  - GOAL_TRIGGER_SMS
  - GOAL_TRIGGER_DEVICE_ADMIN
  - GOAL_TRIGGER_NETWORK

Each goal exposes: priority(), is_complete(), candidate_actions().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.agentic.screen_classifier import ScreenType
from sudarshan_core.engines.agentic.world_model import WorldModel


@dataclass
class ActionCandidate:
    """An action proposed by a Goal for execution by the Planner."""
    action_type: str        # click / input / scroll / back
    target_node_id: str     # n0, n1, w0
    target_label: str       # "Allow", "Grant", "Submit"
    priority: int           # 0 to 100
    reason: str             # "Grant runtime permission"
    input_text: str = ""    # text to enter if input action


class Goal(ABC):
    """Abstract base class for investigation goals."""
    
    @abstractmethod
    def get_name(self) -> str: pass

    @abstractmethod
    def priority(self, world_model: WorldModel, current_screen: Any) -> int: pass

    @abstractmethod
    def is_complete(self, world_model: WorldModel) -> bool: pass

    @abstractmethod
    def candidate_actions(self, world_model: WorldModel, current_screen: Any, ui_nodes: List[Any]) -> List[ActionCandidate]: pass


# ── 1. GOAL_GRANT_PERMISSIONS ──────────────────────────────────────────────────

class GoalGrantPermissions(Goal):
    def get_name(self) -> str: return "GOAL_GRANT_PERMISSIONS"

    def priority(self, world_model: WorldModel, current_screen: Any) -> int:
        return 100 if getattr(current_screen, "semantic_type", "") == ScreenType.SYSTEM_PERMISSION else 30

    def is_complete(self, world_model: WorldModel) -> bool:
        return False

    def candidate_actions(self, world_model: WorldModel, current_screen: Any, ui_nodes: List[Any]) -> List[ActionCandidate]:
        candidates = []
        for idx, n in enumerate(ui_nodes):
            nid = getattr(n, "node_id", f"n{idx}")
            lbl = getattr(n, "text", "") or getattr(n, "desc", "") or getattr(n, "class_name", "")
            lbl_lower = str(lbl).lower()
            if any(w in lbl_lower for w in ["allow", "grant", "while using the app", "always allow"]):
                candidates.append(ActionCandidate(
                    action_type="click",
                    target_node_id=nid,
                    target_label=str(lbl),
                    priority=100,
                    reason="Grant system runtime permission"
                ))
        return candidates


# ── 2. GOAL_TRIGGER_ACCESSIBILITY ─────────────────────────────────────────────

class GoalTriggerAccessibility(Goal):
    def get_name(self) -> str: return "GOAL_TRIGGER_ACCESSIBILITY"

    def priority(self, world_model: WorldModel, current_screen: Any) -> int:
        return 95 if getattr(current_screen, "semantic_type", "") == ScreenType.ACCESSIBILITY_DIALOG else 40

    def is_complete(self, world_model: WorldModel) -> bool:
        return False

    def candidate_actions(self, world_model: WorldModel, current_screen: Any, ui_nodes: List[Any]) -> List[ActionCandidate]:
        candidates = []
        for idx, n in enumerate(ui_nodes):
            nid = getattr(n, "node_id", f"n{idx}")
            lbl = getattr(n, "text", "") or getattr(n, "desc", "") or getattr(n, "class_name", "")
            lbl_lower = str(lbl).lower()
            if any(w in lbl_lower for w in ["accessibility", "enable", "turn on", "on", "installed services"]):
                candidates.append(ActionCandidate(
                    action_type="click",
                    target_node_id=nid,
                    target_label=str(lbl),
                    priority=95,
                    reason="Enable Accessibility Service for malware execution"
                ))
        return candidates


# ── 3. GOAL_TRIGGER_OVERLAY ───────────────────────────────────────────────────

class GoalTriggerOverlay(Goal):
    def get_name(self) -> str: return "GOAL_TRIGGER_OVERLAY"

    def priority(self, world_model: WorldModel, current_screen: Any) -> int:
        return 90 if getattr(current_screen, "semantic_type", "") == ScreenType.OVERLAY_ATTACK else 35

    def is_complete(self, world_model: WorldModel) -> bool:
        return False

    def candidate_actions(self, world_model: WorldModel, current_screen: Any, ui_nodes: List[Any]) -> List[ActionCandidate]:
        candidates = []
        for idx, n in enumerate(ui_nodes):
            nid = getattr(n, "node_id", f"n{idx}")
            lbl = getattr(n, "text", "") or getattr(n, "desc", "") or getattr(n, "class_name", "")
            lbl_lower = str(lbl).lower()
            if any(w in lbl_lower for w in ["allow display over other apps", "permit drawing", "allow", "enable"]):
                candidates.append(ActionCandidate(
                    action_type="click",
                    target_node_id=nid,
                    target_label=str(lbl),
                    priority=90,
                    reason="Grant System Overlay Permission"
                ))
        return candidates


# ── 4. GOAL_TRIGGER_LOGIN / BANKING ────────────────────────────────────────────

class GoalTriggerLogin(Goal):
    def get_name(self) -> str: return "GOAL_TRIGGER_LOGIN"

    def priority(self, world_model: WorldModel, current_screen: Any) -> int:
        return 85 if getattr(current_screen, "semantic_type", "") == ScreenType.BANK_LOGIN else 50

    def is_complete(self, world_model: WorldModel) -> bool:
        return False

    def candidate_actions(self, world_model: WorldModel, current_screen: Any, ui_nodes: List[Any]) -> List[ActionCandidate]:
        candidates = []
        for idx, n in enumerate(ui_nodes):
            nid = getattr(n, "node_id", f"n{idx}")
            lbl = getattr(n, "text", "") or getattr(n, "desc", "") or getattr(n, "class_name", "")
            is_input = getattr(n, "is_input", False) or (isinstance(n, dict) and n.get("is_input"))
            lbl_lower = str(lbl).lower()

            if is_input:
                val = "testuser" if "user" in lbl_lower or "name" in lbl_lower else "Password123!"
                candidates.append(ActionCandidate(
                    action_type="input",
                    target_node_id=nid,
                    target_label=str(lbl),
                    priority=85,
                    reason="Fill input field in banking login form",
                    input_text=val
                ))
            elif any(w in lbl_lower for w in ["submit", "login", "sign in", "continue", "proceed"]):
                candidates.append(ActionCandidate(
                    action_type="click",
                    target_node_id=nid,
                    target_label=str(lbl),
                    priority=90,
                    reason="Submit banking login form"
                ))
        return candidates


# ── Goal Suite Registry ────────────────────────────────────────────────────────

def get_all_goals() -> List[Goal]:
    """Return list of default Goal instances ordered by priority."""
    return [
        GoalGrantPermissions(),
        GoalTriggerAccessibility(),
        GoalTriggerOverlay(),
        GoalTriggerLogin(),
    ]
