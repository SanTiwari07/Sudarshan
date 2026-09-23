"""
Jev Planner Adapter (Phase 2 - Real API)
"""
from typing import Any, Dict, Optional, List
import json
import logging
import os
import time
import httpx

from sudarshan_core.engines.agentic.perception import Observation
from sudarshan_core.engines.agentic.agent_memory import AgentMemory
from sudarshan_core.engines.agentic.goal_tracker import GoalTracker
from sudarshan_core.engines.agentic.exploration_engine import ExplorationGraph, ActionItem

logger = logging.getLogger(__name__)

class JevPlanner:
    def __init__(
        self,
        api_key: Optional[str],
        device_serial: str,
        package_name: str,
        action_budget: int = 25,
        benchmark: Optional[Any] = None,
        adb_path: str = "adb",
        exploration: Optional[ExplorationGraph] = None,
    ) -> None:
        self.api_key = api_key
        self.device_serial = device_serial
        self.package_name = package_name
        self.exploration = exploration
        
        self.api_url = os.getenv("TYPESAFE_JEV_API_URL", "https://api.typesafe.ai/v1/systemone")
        self.model = os.getenv("TYPESAFE_JEV_MODEL", "jev-latest")
        self.timeout = float(os.getenv("JEV_TIMEOUT_SECONDS", "2.0"))
        self.provider = os.getenv("SUDARSHAN_JEV_PROVIDER", "real").lower()
        
        self.last_failure_reason = ""
        self.last_confidence = 0.0
        self.last_latency_ms = 0.0
        
        logger.info(f"[JevPlanner] Jev Provider: {self.provider.upper()} (model={self.model}, endpoint={self.api_url})")

    async def decide(
        self,
        obs: Observation,
        memory: AgentMemory,
        goals: GoalTracker,
        *,
        deadline_seconds: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        self.last_failure_reason = ""
        self.last_confidence = 0.0
        self.last_latency_ms = 0.0
        
        t0 = time.monotonic()
        if not self.exploration:
            self.last_failure_reason = "JEV_INTERNAL_ERROR"
            logger.error("[JevPlanner] No exploration graph attached. Returning None.")
            return None

        # Look up current state
        state_id = self.exploration._current_state_id
        if not state_id:
            self.last_failure_reason = "JEV_INTERNAL_ERROR"
            logger.warning("[JevPlanner] No current state ID. Returning None.")
            return None

        current_state = self.exploration.states.get(state_id)
        if not current_state:
            self.last_failure_reason = "JEV_INTERNAL_ERROR"
            logger.warning(f"[JevPlanner] State {state_id} not found. Returning None.")
            return None

        candidates = current_state.unexplored_actions()
        if not candidates:
            self.last_failure_reason = "JEV_NO_CANDIDATES"
            logger.debug("[JevPlanner] No unexplored candidates available.")
            return None

        if self.provider == "mock":
            jev_response = await self._invoke_mock(obs, goals, candidates)
        else:
            if not self.api_key:
                self.last_failure_reason = "JEV_MISSING_CREDENTIALS"
                logger.error("[JevPlanner] Missing TYPESAFE_JEV_API_KEY.")
                return None
    
            jev_payload = self._serialize_candidates(obs, goals, candidates)
            jev_response = await self._invoke_jev(jev_payload)
        
        result = self._validate_and_deserialize(jev_response, candidates)
        
        total_latency = time.monotonic() - t0
        self.last_latency_ms = total_latency * 1000.0
        
        # Telemetry
        logger.info(
            f"[JevPlanner] Decision metrics: state_id={state_id}, candidates={len(candidates)}, "
            f"selected={result.get('_action_id') if result else 'None'}, "
            f"confidence={jev_response.get('confidence', 0.0) if jev_response else 0.0}, "
            f"jev_latency={jev_response.get('latency', 0.0) if jev_response else 0.0:.2f}s, "
            f"total_latency={total_latency:.2f}s"
        )
        return result

    async def _invoke_mock(self, obs: Observation, goals: GoalTracker, candidates: List[ActionItem]) -> Dict[str, Any]:
        """Offline simulator for Jev."""
        import asyncio
        await asyncio.sleep(0.01)  # Simulated latency
        
        next_goal = goals.next_priority_goal() if goals else None
        goal_name = next_goal.name.lower() if next_goal else ""
        
        selected_cand = None
        
        # Rule 1: Prefer input fields when goal requires data entry
        needs_input = any(kw in goal_name for kw in ["login", "credential", "otp", "password", "input", "form"])
        if needs_input:
            for c in candidates:
                if getattr(c, "is_input", False) or getattr(c, "action_type", "") in ("type_text", "input"):
                    selected_cand = c
                    break
        
        # Rule 2: Prefer buttons relevant to goal
        if not selected_cand and goal_name:
            goal_words = set(goal_name.split())
            for c in candidates:
                if getattr(c, "is_clickable", False) or getattr(c, "action_type", "") in ("tap", "click_text", "click"):
                    lbl = getattr(c, "label", "").lower()
                    if any(w in lbl for w in goal_words if len(w) > 3):
                        selected_cand = c
                        break
                        
        # Rule 3: Prefer navigation/clicks
        if not selected_cand:
            for c in candidates:
                if getattr(c, "is_clickable", False) or getattr(c, "action_type", "") in ("tap", "click", "click_text"):
                    selected_cand = c
                    break
                    
        # Rule 4: Fallback to first candidate
        if not selected_cand and candidates:
            selected_cand = candidates[0]
            
        if not selected_cand:
            self.last_failure_reason = "JEV_INVALID_RESPONSE"
            return {}
            
        cand_id = getattr(selected_cand, "node_id", "") or getattr(selected_cand, "action_id", "")
        
        return {
            "selected_id": cand_id,
            "confidence": 0.95,
            "probabilities": {cand_id: 0.95},
            "latency": 0.01,
            "model": "jev-mock",
            "provider": "jev_mock",
            "reason": "offline_test"
        }

    def _serialize_candidates(self, obs: Observation, goals: GoalTracker, candidates: List[ActionItem]) -> Dict[str, Any]:
        next_goal = goals.next_priority_goal()
        goal_name = next_goal.name if next_goal else "general"
        
        state_text = f"Goal: {goal_name}\n"
        state_text += f"Package: {self.package_name}\n"
        state_text += f"Screen: {obs.activity}\n\n"
        state_text += "Available Actions:\n"
        
        choices = {}
        for c in candidates:
            cid = c.node_id or c.action_id
            class_name = getattr(c, 'class_name', '')
            choices[cid] = f"{c.action_type.upper()} '{c.label}' (class: {class_name})"
            
        return {
            "model": self.model,
            "state": state_text.strip(),
            "questions": {
                "action": {
                    "type": "choice",
                    "criteria": choices,
                    "instructions": "Select the best action to advance the current investigation goal."
                }
            }
        }

    async def _invoke_jev(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.monotonic()
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.api_url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                
                answers = data.get("answers", {})
                action_answer = answers.get("action", {})
                selected_id = action_answer.get("choice")
                
                if not selected_id:
                    self.last_failure_reason = "JEV_INVALID_RESPONSE"
                    logger.warning("[JevPlanner] API response missing 'choice' field in answers.action")
                    return {}
                    
                return {
                    "selected_id": selected_id,
                    "confidence": action_answer.get("confidence", 0.0),
                    "probabilities": action_answer.get("probabilities", {}),
                    "latency": time.monotonic() - t0,
                    "model": data.get("model", self.model)
                }
                
        except httpx.HTTPStatusError as e:
            self.last_failure_reason = "JEV_HTTP_ERROR"
            logger.error(f"[JevPlanner] HTTP {e.response.status_code} Error: {e.response.text}")
        except httpx.TimeoutException:
            self.last_failure_reason = "JEV_TIMEOUT"
            logger.error(f"[JevPlanner] API Request Timeout after {self.timeout}s")
        except json.JSONDecodeError:
            self.last_failure_reason = "JEV_INVALID_RESPONSE"
            logger.error("[JevPlanner] Failed to parse JSON response")
        except httpx.RequestError as e:
            self.last_failure_reason = "JEV_NETWORK_ERROR"
            logger.error(f"[JevPlanner] Network Error: {str(e)}")
        except Exception as e:
            self.last_failure_reason = "JEV_INTERNAL_ERROR"
            logger.error(f"[JevPlanner] Unexpected Error: {str(e)}")
            
        return {}

    def _validate_and_deserialize(self, response: Dict[str, Any], candidates: List[ActionItem]) -> Optional[Dict[str, Any]]:
        if not response:
            return None
            
        selected_id = response.get("selected_id")
        if not selected_id:
            # self.last_failure_reason should already be set by _invoke_jev if it was an error
            return None

        # 1. & 2. Verify selected_id exists in the bounded candidate list
        selected_cand = None
        for c in candidates:
            if (c.node_id or c.action_id) == selected_id:
                selected_cand = c
                break

        if not selected_cand:
            self.last_failure_reason = "JEV_INVALID_CHOICE"
            logger.warning(f"[JevPlanner] Validation Failed: ID {selected_id} not in candidates.")
            return None

        # 3. & 4. Ensure it's not stale/failed/blocked
        if getattr(selected_cand, 'failed', False) or getattr(selected_cand, 'blocked', False) or getattr(selected_cand, 'resolved', False):
            self.last_failure_reason = "JEV_STALE_CHOICE"
            logger.warning(f"[JevPlanner] Validation Failed: ID {selected_id} is already failed, blocked, or resolved.")
            return None

        self.last_failure_reason = "JEV_SUCCESS"
        self.last_confidence = response.get("confidence", 0.0)

        raw_type = selected_cand.action_type
        if raw_type == "click":
            tool_name = "tap"
        elif raw_type == "input":
            tool_name = "type_text"
        else:
            tool_name = raw_type

        # 5. Map back to ActionDispatcher format
        action_dict = {
            "tool": tool_name,
            "node_id": selected_cand.node_id,
            "_action_id": selected_cand.action_id,
            "text": selected_cand.label,
            "_selected_by": "jev_planner",
            "_jev_confidence": self.last_confidence,
        }

        if hasattr(selected_cand, 'center_x') and hasattr(selected_cand, 'center_y'):
            action_dict["x"] = selected_cand.center_x
            action_dict["y"] = selected_cand.center_y

        if hasattr(selected_cand, 'field_kind') and selected_cand.field_kind:
            action_dict["field_hint"] = selected_cand.field_kind

        return action_dict

    def invalidate_cache_for_screen(self, screen_hash: str) -> None:
        pass

