"""
Hybrid Planner Architecture (Phase 3)
"""
from typing import Any, Dict, Optional
import logging
import os
import time

from sudarshan_core.engines.agentic.perception import Observation
from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.goal_tracker import GoalTracker
from sudarshan_core.engines.agentic.jev_planner import JevPlanner
from sudarshan_core.engines.agentic.planner import AgentPlanner

logger = logging.getLogger(__name__)

class HybridPlanner:
    def __init__(
        self,
        jev_planner: JevPlanner,
        agent_planner: AgentPlanner,
    ) -> None:
        self.jev_planner = jev_planner
        self.agent_planner = agent_planner
        
        self.confidence_threshold = float(os.getenv("JEV_CONFIDENCE_THRESHOLD", "0.7"))
        
        logger.info("[HybridPlanner] Initialized Hybrid (Jev -> Gemini) Planner.")

    def _vision_requires_gemini(self, obs: Observation) -> bool:
        if not obs.screenshot_taken:
            return False
            
        reason = (obs.vision_reason or "").lower()
        
        # Jev struggles if the DOM is not representative of the visual screen
        if "ui_xml_empty" in reason or "no_actionable_nodes" in reason or "webview" in reason or "unlabeled" in reason:
            return True
            
        return False

    async def decide(
        self,
        obs: Observation,
        memory: AgentMemory,
        goals: GoalTracker,
        *,
        deadline_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        
        # Metrics
        t0 = time.monotonic()
        metrics = {
            "planner_mode": "hybrid",
            "jev_attempted": False,
            "jev_success": False,
            "jev_failure_reason": "",
            "jev_latency_ms": 0.0,
            "gemini_called": False,
            "gemini_latency_ms": 0.0,
            "total_planner_latency_ms": 0.0,
            "selected_action": "",
            "fallback_used": False
        }
        
        try:
            # 1. Vision Check
            if self._vision_requires_gemini(obs):
                metrics["jev_failure_reason"] = "JEV_UNSUPPORTED_SCREEN"
                logger.info(f"[HybridPlanner] Bypassing Jev due to vision requirement (reason: {obs.vision_reason})")
            else:
                # 2. Call Jev
                metrics["jev_attempted"] = True
                action = await self.jev_planner.decide(obs, memory, goals, deadline_seconds=deadline_seconds)
                
                metrics["jev_latency_ms"] = self.jev_planner.last_latency_ms
                metrics["jev_failure_reason"] = self.jev_planner.last_failure_reason
                
                if action and metrics["jev_failure_reason"] == "JEV_SUCCESS":
                    if self.jev_planner.last_confidence and self.jev_planner.last_confidence < self.confidence_threshold:
                        metrics["jev_failure_reason"] = "JEV_LOW_CONFIDENCE"
                        logger.info(f"[HybridPlanner] Jev low confidence ({self.jev_planner.last_confidence} < {self.confidence_threshold}). Escalating.")
                    else:
                        metrics["jev_success"] = True
                        metrics["selected_action"] = action.get("tool", "")
                        return action
            
            # 3. Fallback to Gemini
            t_gemini = time.monotonic()
            metrics["gemini_called"] = True
            
            # Adjust deadline for Gemini
            remaining = deadline_seconds
            if remaining is not None:
                remaining -= (time.monotonic() - t0)
                if remaining <= 0:
                    logger.warning("[HybridPlanner] No budget left for Gemini escalation.")
                    return None
            
            action = await self.agent_planner.decide(obs, memory, goals, deadline_seconds=remaining)
            
            metrics["gemini_latency_ms"] = (time.monotonic() - t_gemini) * 1000.0
            
            if action:
                metrics["selected_action"] = action.get("tool", "")
            else:
                metrics["fallback_used"] = True
                
            return action
            
        finally:
            metrics["total_planner_latency_ms"] = (time.monotonic() - t0) * 1000.0
            logger.info(f"[HybridPlanner_Metrics] {metrics}")

    def invalidate_cache_for_screen(self, screen_hash: str) -> None:
        if hasattr(self.agent_planner, 'invalidate_cache_for_screen'):
            self.agent_planner.invalidate_cache_for_screen(screen_hash)
        if hasattr(self.jev_planner, 'invalidate_cache_for_screen'):
            self.jev_planner.invalidate_cache_for_screen(screen_hash)

