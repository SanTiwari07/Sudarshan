"""
SUDARSHAN - World Model (Persistent Exploration Memory)
========================================================
Maintains structured memory of explored application states, visited screens,
permission prompts, login forms, banking triggers, and failed actions.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from sudarshan_core.engines.agentic.screen_classifier import ScreenType
from sudarshan_core.engines.agentic.screen_graph import ScreenGraphBuilder, ScreenNode

logger = logging.getLogger(__name__)


class WorldModel:
    """
    Persistent memory store for one dynamic analysis session.
    """

    def __init__(self, package_name: str = "") -> None:
        self.package_name = package_name
        self.screen_graph = ScreenGraphBuilder()
        
        # Specific semantic tracking
        self.known_login_forms: Set[str] = set()       # screen hashes
        self.known_otp_screens: Set[str] = set()       # screen hashes
        self.known_overlay_screens: Set[str] = set()    # screen hashes
        self.known_permission_dialogs: Set[str] = set()# screen hashes
        self.known_banking_apps: Set[str] = set()      # package names
        
        # Failed actions: set of (screen_hash, action_target_id)
        self.failed_actions: Set[tuple] = set()

        self._lock = threading.Lock()

    def update_observation(
        self,
        activity_name: str,
        package_name: str,
        ui_nodes: List[Any],
        raw_xml: str = ""
    ) -> ScreenNode:
        """Process observation and update persistent state memory."""
        node = self.screen_graph.process_observation(activity_name, package_name, ui_nodes, raw_xml)
        
        with self._lock:
            shash = node.screen_hash
            stype = node.semantic_type

            if stype == ScreenType.BANK_LOGIN:
                self.known_login_forms.add(shash)
            elif stype == ScreenType.OTP_SCREEN:
                self.known_otp_screens.add(shash)
            elif stype == ScreenType.OVERLAY_ATTACK:
                self.known_overlay_screens.add(shash)
            elif stype == ScreenType.SYSTEM_PERMISSION or stype == ScreenType.ACCESSIBILITY_DIALOG:
                self.known_permission_dialogs.add(shash)

            if package_name and package_name != self.package_name:
                self.known_banking_apps.add(package_name)

        return node

    def record_failed_action(self, screen_hash: str, action_target: str) -> None:
        """Mark an action as failed so the planner avoids repeating it."""
        with self._lock:
            self.failed_actions.add((screen_hash, action_target))
            logger.warning("[WorldModel] Marked failed action on %s -> %s", screen_hash[:6], action_target)

    def is_action_failed(self, screen_hash: str, action_target: str) -> bool:
        """Return True if action previously failed on this screen."""
        with self._lock:
            return (screen_hash, action_target) in self.failed_actions

    def get_summary(self) -> Dict[str, Any]:
        """Return JSON summary of world model state."""
        with self._lock:
            return {
                "package_name": self.package_name,
                "total_screens": len(self.screen_graph.get_nodes()),
                "login_forms_found": len(self.known_login_forms),
                "otp_screens_found": len(self.known_otp_screens),
                "overlay_screens_found": len(self.known_overlay_screens),
                "permission_dialogs_found": len(self.known_permission_dialogs),
                "failed_actions_count": len(self.failed_actions),
            }
