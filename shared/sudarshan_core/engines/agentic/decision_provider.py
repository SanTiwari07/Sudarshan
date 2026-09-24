"""SUDARSHAN — Unified Decision Provider Abstraction.

Defines a standardized interface (`DecisionProvider`) for System-1 and System-2
exploration decision engines:
- Jev (TypeSafe API)
- Laya (Local / Container System-1)
- Gemini (AgentPlanner / Vision System-2)
- Rule-based (Deterministic Exploration Graph)
- Cascading / Hybrid orchestrators

CRITICAL SAFETY PRINCIPLES:
- Providers ONLY propose UI actions from candidate pools or screen observations.
- Providers NEVER determine BFCI, STEI, FRS, malware verdicts, or threat vectors.
- Risk scoring remains strictly deterministic within the RiskEngine.
"""

from __future__ import annotations

import abc
import logging
from typing import Any, Dict, List, Optional

from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.goal_tracker import GoalTracker
from sudarshan_core.engines.agentic.perception import Observation

logger = logging.getLogger("sudarshan.agentic.decision_provider")


class DecisionProvider(abc.ABC):
    """Abstract interface for all SUDARSHAN action decision providers."""

    @abc.abstractmethod
    async def decide(
        self,
        obs: Observation,
        memory: AgentMemory,
        goals: GoalTracker,
        *,
        deadline_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Evaluate screen observation and return a proposed canonical action dict or None."""
        pass

    def invalidate_cache_for_screen(self, screen_hash: str) -> None:
        """Invalidate any cached plans or tokens for the specified screen hash."""
        pass


class JevDecisionProvider(DecisionProvider):
    """Adapter wrapping JevPlanner into the DecisionProvider interface."""

    def __init__(self, jev_planner: Any) -> None:
        self.planner = jev_planner

    async def decide(
        self,
        obs: Observation,
        memory: AgentMemory,
        goals: GoalTracker,
        *,
        deadline_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        return await self.planner.decide(obs, memory, goals, deadline_seconds=deadline_seconds)

    def invalidate_cache_for_screen(self, screen_hash: str) -> None:
        if hasattr(self.planner, "invalidate_cache_for_screen"):
            self.planner.invalidate_cache_for_screen(screen_hash)


class LayaDecisionProvider(DecisionProvider):
    """Adapter wrapping LayaPlanner into the DecisionProvider interface."""

    def __init__(self, laya_planner: Any) -> None:
        self.planner = laya_planner

    async def decide(
        self,
        obs: Observation,
        memory: AgentMemory,
        goals: GoalTracker,
        *,
        deadline_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        return await self.planner.decide(obs, memory, goals, deadline_seconds=deadline_seconds)

    def invalidate_cache_for_screen(self, screen_hash: str) -> None:
        if hasattr(self.planner, "invalidate_cache_for_screen"):
            self.planner.invalidate_cache_for_screen(screen_hash)


class GeminiDecisionProvider(DecisionProvider):
    """Adapter wrapping AgentPlanner (Gemini) into the DecisionProvider interface."""

    def __init__(self, agent_planner: Any) -> None:
        self.planner = agent_planner

    async def decide(
        self,
        obs: Observation,
        memory: AgentMemory,
        goals: GoalTracker,
        *,
        deadline_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        return await self.planner.decide(obs, memory, goals, deadline_seconds=deadline_seconds)

    def invalidate_cache_for_screen(self, screen_hash: str) -> None:
        if hasattr(self.planner, "invalidate_cache_for_screen"):
            self.planner.invalidate_cache_for_screen(screen_hash)


class RuleDecisionProvider(DecisionProvider):
    """Deterministic rule-based decision provider reading from the ExplorationGraph."""

    def __init__(self, exploration: Any) -> None:
        self.exploration = exploration

    async def decide(
        self,
        obs: Observation,
        memory: AgentMemory,
        goals: GoalTracker,
        *,
        deadline_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.exploration:
            return None
        current_state_id = self.exploration._current_state_id
        if not current_state_id:
            return None
        action = self.exploration.get_next_action(state_id=current_state_id, memory=memory)
        if action:
            action["_selected_by"] = "rule_planner"
        return action

    def invalidate_cache_for_screen(self, screen_hash: str) -> None:
        pass


class CascadingDecisionProvider(DecisionProvider):
    """Cascading decision provider that attempts providers in prioritized order.

    Supports vision-gating (bypassing text-only System-1 models when vision is required)
    and fallback ladders.
    """

    def __init__(
        self,
        providers: List[Tuple[str, DecisionProvider]],
        vision_provider: Optional[DecisionProvider] = None,
    ) -> None:
        self.providers = providers
        self.vision_provider = vision_provider

    def _vision_requires_gemini(self, obs: Observation) -> bool:
        """Detect screens that cannot be navigated via text/UI hierarchy alone."""
        act = (getattr(obs, "activity", "") or "").lower()
        if "webview" in act or "browser" in act:
            return True
        nodes = getattr(obs, "ui_nodes", []) or []
        if not nodes:
            return True
        labeled_nodes = [n for n in nodes if getattr(n, "text", "") or getattr(n, "content_desc", "")]
        return len(labeled_nodes) == 0

    async def decide(
        self,
        obs: Observation,
        memory: AgentMemory,
        goals: GoalTracker,
        *,
        deadline_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        # If visual reasoning is required and a vision provider is configured, route there first
        if self._vision_requires_gemini(obs) and self.vision_provider:
            logger.debug("[CascadingDecisionProvider] Vision required; routing to vision provider.")
            return await self.vision_provider.decide(obs, memory, goals, deadline_seconds=deadline_seconds)

        # Attempt cascade in prioritized order
        for name, provider in self.providers:
            try:
                action = await provider.decide(obs, memory, goals, deadline_seconds=deadline_seconds)
                if action is not None:
                    logger.debug("[CascadingDecisionProvider] Action resolved by '%s'.", name)
                    return action
            except Exception as exc:
                logger.warning("[CascadingDecisionProvider] Provider '%s' raised exception: %s", name, exc)
                continue

        logger.info("[CascadingDecisionProvider] All providers in cascade exhausted without action.")
        return None

    def invalidate_cache_for_screen(self, screen_hash: str) -> None:
        for _, provider in self.providers:
            provider.invalidate_cache_for_screen(screen_hash)
        if self.vision_provider:
            self.vision_provider.invalidate_cache_for_screen(screen_hash)


def create_decision_provider(
    mode: str,
    *,
    jev_planner: Optional[Any] = None,
    laya_planner: Optional[Any] = None,
    agent_planner: Optional[Any] = None,
    exploration: Optional[Any] = None,
) -> DecisionProvider:
    """Factory creating the appropriate DecisionProvider hierarchy from configuration."""
    mode = (mode or "").lower().strip()

    j_prov = JevDecisionProvider(jev_planner) if jev_planner else None
    l_prov = LayaDecisionProvider(laya_planner) if laya_planner else None
    g_prov = GeminiDecisionProvider(agent_planner) if agent_planner else None
    r_prov = RuleDecisionProvider(exploration) if exploration else None

    if mode == "laya":
        if l_prov:
            return l_prov
        logger.warning("[DecisionProvider] Mode 'laya' requested but laya_planner is None; falling back to agent_planner.")
        return g_prov or r_prov  # type: ignore

    if mode == "laya_hybrid":
        cascade_list: List[Tuple[str, DecisionProvider]] = []
        if l_prov:
            cascade_list.append(("laya", l_prov))
        if g_prov:
            cascade_list.append(("gemini", g_prov))
        if r_prov:
            cascade_list.append(("rules", r_prov))
        return CascadingDecisionProvider(cascade_list, vision_provider=g_prov)

    if mode == "jev":
        if j_prov:
            return j_prov
        logger.warning("[DecisionProvider] Mode 'jev' requested but jev_planner is None; falling back to agent_planner.")
        return g_prov or r_prov  # type: ignore

    if mode == "hybrid":
        cascade_list = []
        if j_prov:
            cascade_list.append(("jev", j_prov))
        if g_prov:
            cascade_list.append(("gemini", g_prov))
        if r_prov:
            cascade_list.append(("rules", r_prov))
        return CascadingDecisionProvider(cascade_list, vision_provider=g_prov)

    # Default to Gemini / AgentPlanner
    if g_prov:
        return g_prov
    if r_prov:
        return r_prov
    raise ValueError(f"Unable to construct DecisionProvider for mode '{mode}'")
