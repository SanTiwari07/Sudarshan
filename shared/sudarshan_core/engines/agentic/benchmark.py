"""
SUDARSHAN - Agentic Benchmark Collector
=========================================
Collects metrics during Agentic Explorer runs.

IMPORTANT - Benchmark Framework Scope:
  This module performs DATA COLLECTION only.

  The acceptance gate specified in the requirements (corpus comparison across
  benign / banking trojan / SMS fraud / RAT / spyware / overlay malware /
  packer / obfuscated malware categories with false positive/negative tracking)
  is a SEPARATE follow-up phase that requires:
    1. A labeled APK corpus to be assembled.
    2. The explorer run on every sample.
    3. Results from benchmark.json files compared offline.

  This PR implements the metric infrastructure only. The corpus evaluation
  is outside the scope of this implementation and must be tracked separately.

Metrics collected:
  - unique_screens_visited
  - ui_elements_interacted
  - frida_events_by_category (dict)
  - frida_unique_hook_types (set → count)
  - bfci_categories_triggered (proxy: non-empty event lists)
  - lln_calls_made
  - actions_taken
  - redundant_actions (same screen+tool+target repeated)
  - screenshots_taken
  - fallback_activations (times FallbackPlanner was used)
  - total_elapsed_seconds
  - goals_completed / goals_skipped / goals_failed

Usage::

    bm = BenchmarkCollector(package_name="com.example.app")
    bm.record_action(screen_hash="abc", tool="tap", target="n3", redundant=False)
    bm.record_frida_event(category="accessibility", hook="onAccessibilityEvent")
    bm.record_llm_call()
    bm.set_goal_summary(completed=5, skipped=8, failed=2)
    bm.flush(Path("benchmark.json"))
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


class BenchmarkCollector:
    """
    Thread-safe metrics accumulator for one analysis session.
    """

    def __init__(self, package_name: str) -> None:
        self.package_name  = package_name
        self._start_time   = time.monotonic()
        self._lock         = threading.Lock()

        # ── Coverage metrics ───────────────────────────────────────────────────
        self._unique_screens:    Set[str]         = set()
        self._elements_interacted: int            = 0
        self._redundant_actions: int              = 0

        # ── Frida metrics ──────────────────────────────────────────────────────
        # category → count
        self._frida_events:      Dict[str, int]   = defaultdict(int)
        # All unique hook strings seen
        self._frida_hooks:       Set[str]         = set()

        # ── Efficiency metrics ─────────────────────────────────────────────────
        self._llm_calls:         int              = 0
        # Token accounting. Gemini reports usage per response; recording it is
        # the only way a run's LLM cost can be reconstructed afterwards.
        self._prompt_tokens:     int              = 0
        self._output_tokens:     int              = 0
        self._total_tokens:      int              = 0
        self._llm_models_used:   Set[str]         = set()
        self._actions_taken:     int              = 0
        self._screenshots_taken: int              = 0
        self._fallback_activations: int           = 0

        # ── Goal summary (set by caller at end of run) ────────────────────────
        self._goals_completed:   int              = 0
        self._goals_skipped:     int              = 0
        self._goals_failed:      int              = 0

    # ── Recording methods ──────────────────────────────────────────────────────

    def record_screen(self, screen_hash: str) -> None:
        with self._lock:
            self._unique_screens.add(screen_hash)

    def record_action(self, screen_hash: str, tool: str, target: str, redundant: bool) -> None:
        with self._lock:
            self._actions_taken += 1
            if not redundant:
                self._elements_interacted += 1
            else:
                self._redundant_actions += 1

    def record_frida_event(self, category: str, hook: str) -> None:
        with self._lock:
            self._frida_events[category] += 1
            if hook:
                self._frida_hooks.add(hook)

    def record_llm_call(
        self,
        prompt_tokens: int = 0,
        output_tokens: int = 0,
        total_tokens:  int = 0,
        model:         str = "",
    ) -> None:
        """
        Record ONE LLM API call.

        Called from the planner at the actual request site, not from the agent
        loop: a schema-validation retry issues a second request, and counting in
        the loop attributed both to a single call.
        """
        with self._lock:
            self._llm_calls += 1
            self._prompt_tokens += max(0, int(prompt_tokens or 0))
            self._output_tokens += max(0, int(output_tokens or 0))
            self._total_tokens  += max(0, int(total_tokens or 0))
            if model:
                self._llm_models_used.add(model)

    def record_screenshot(self) -> None:
        with self._lock:
            self._screenshots_taken += 1

    def record_fallback_activation(self) -> None:
        with self._lock:
            self._fallback_activations += 1

    def set_goal_summary(self, completed: int, skipped: int, failed: int) -> None:
        with self._lock:
            self._goals_completed = completed
            self._goals_skipped   = skipped
            self._goals_failed    = failed

    # ── Report output ──────────────────────────────────────────────────────────

    def build_report(self) -> Dict:
        elapsed = time.monotonic() - self._start_time
        with self._lock:
            bfci_categories_triggered = [
                cat for cat, count in self._frida_events.items() if count > 0
            ]
            return {
                "benchmark_version":       "1.0",
                "generated_at":            datetime.now(tz=timezone.utc).isoformat(),
                "package_name":            self.package_name,
                "total_elapsed_seconds":   round(elapsed, 1),

                # Coverage
                "unique_screens_visited":  len(self._unique_screens),
                "ui_elements_interacted":  self._elements_interacted,
                "redundant_actions":       self._redundant_actions,

                # Frida
                # Additive LLM cost fields - never rename or remove existing keys.
                "llm_prompt_tokens":        self._prompt_tokens,
                "llm_output_tokens":        self._output_tokens,
                "llm_total_tokens":         self._total_tokens,
                "llm_models_used":          sorted(self._llm_models_used),

                "frida_events_by_category": dict(self._frida_events),
                "frida_unique_hook_types":  len(self._frida_hooks),
                "bfci_categories_triggered": bfci_categories_triggered,
                "bfci_category_count":      len(bfci_categories_triggered),

                # Efficiency
                "actions_taken":           self._actions_taken,
                "llm_calls_made":          self._llm_calls,
                "screenshots_taken":       self._screenshots_taken,
                "fallback_activations":    self._fallback_activations,

                # Goals
                "goals_completed":         self._goals_completed,
                "goals_skipped":           self._goals_skipped,
                "goals_failed":            self._goals_failed,

                # NOTE: Full corpus comparison (benign/trojan/RAT/spyware etc.)
                # with false positive/negative tracking is a SEPARATE follow-up
                # acceptance gate phase. This file provides per-run data only.
                "corpus_benchmark_scope":  "per_run_only__corpus_comparison_is_separate_phase",
            }

    def flush(self, output_path: Path) -> None:
        """Write benchmark data to JSON. Idempotent."""
        report = self.build_report()
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            logger.info(f"[Benchmark] Flushed metrics → {output_path}")
        except Exception as e:
            logger.error(f"[Benchmark] Failed to write benchmark.json: {e}")
