"""SUDARSHAN — Laya Decision Engine Benchmark Script.

Measures:
- Cold model loading time
- First inference latency
- Warm inference latency (mean, median, p95 across 20 iterations)
- RAM and VRAM consumption before and after
- Throughput (decisions/sec)
- Scaling across candidate pool sizes:
    - Small (3 candidates)
    - Medium (10 candidates)
    - Large (25 candidates)
"""

from __future__ import annotations

import argparse
import gc
import json
import logging
import os
import statistics
import sys
import time
from typing import Any, Dict, List

import psutil
import torch

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("benchmark_laya")


def get_memory_info() -> Dict[str, float]:
    """Return system RAM and GPU VRAM in megabytes."""
    process = psutil.Process()
    ram_mb = process.memory_info().rss / (1024 * 1024)

    vram_mb = 0.0
    if torch.cuda.is_available():
        vram_mb = torch.cuda.memory_allocated() / (1024 * 1024)

    return {"ram_mb": ram_mb, "vram_mb": vram_mb}


def generate_candidate_questions(num_candidates: int) -> Dict[str, Any]:
    """Generate mock candidate action question payload."""
    criteria = {}
    for i in range(num_candidates):
        cid = f"node_btn_{i:02d}"
        criteria[cid] = f"TAP 'Button {i}' (class: android.widget.Button, bounds: [0, {i*40}, 1080, {(i+1)*40}])"

    state = (
        "Screen: com.example.bank/AccountOverviewActivity\n"
        "Goal: transfer_funds - Select recipient and amount\n"
        "Package: com.example.bank\n"
        "Depth: 3"
    )

    return {
        "state": state,
        "questions": {
            "action": {
                "type": "choice",
                "instructions": "Select the best action to advance the fund transfer workflow.",
                "criteria": criteria,
            }
        },
    }


def run_benchmark(model_id: str = "convaiinnovations/laya-typed-decisions", runs: int = 20, device: str = "cpu") -> Dict[str, Any]:
    import laya

    logger.info("==================================================")
    logger.info(" SUDARSHAN — LAYA BENCHMARK SUITE")
    logger.info(" Model: %s | Device: %s | Runs: %d", model_id, device, runs)
    logger.info("==================================================")

    mem_before = get_memory_info()
    logger.info("Baseline Memory -> RAM: %.1f MB | VRAM: %.1f MB", mem_before["ram_mb"], mem_before["vram_mb"])

    # 1. Cold Load Timing
    t_start_load = time.perf_counter()
    try:
        agent = laya.load(model_id, device=device)
        cold_load_sec = time.perf_counter() - t_start_load
        logger.info("Cold Model Load: %.3f s", cold_load_sec)
    except Exception as exc:
        logger.error("Failed to load model '%s': %s", model_id, exc)
        return {"error": str(exc), "cold_load_sec": None}

    mem_after_load = get_memory_info()
    load_ram_delta = mem_after_load["ram_mb"] - mem_before["ram_mb"]
    load_vram_delta = mem_after_load["vram_mb"] - mem_before["vram_mb"]
    logger.info(
        "Memory after load -> RAM: %.1f MB (Delta: +%.1f MB) | VRAM: %.1f MB (Delta: +%.1f MB)",
        mem_after_load["ram_mb"], load_ram_delta, mem_after_load["vram_mb"], load_vram_delta
    )

    # 2. First Inference Latency (Cold Inference)
    cold_payload = generate_candidate_questions(5)
    t_first_start = time.perf_counter()
    _ = agent.predict(cold_payload["state"], cold_payload["questions"])
    first_inference_ms = (time.perf_counter() - t_first_start) * 1000.0
    logger.info("First Inference Latency: %.2f ms", first_inference_ms)

    # 3. Candidate Pool Scaling Benchmarks
    candidate_scales = [3, 10, 25]
    results_by_scale = {}

    for pool_size in candidate_scales:
        payload = generate_candidate_questions(pool_size)
        latencies_ms: List[float] = []

        logger.info("--- Testing candidate pool size: %d ---", pool_size)
        for i in range(runs):
            t0 = time.perf_counter()
            resp = agent.predict(payload["state"], payload["questions"])
            dt_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(dt_ms)

        mean_ms = statistics.mean(latencies_ms)
        median_ms = statistics.median(latencies_ms)
        p95_ms = statistics.quantiles(latencies_ms, n=20)[18] if len(latencies_ms) >= 20 else max(latencies_ms)
        qps = 1000.0 / mean_ms if mean_ms > 0 else 0.0

        logger.info("Pool %d -> Mean: %.2f ms | Median: %.2f ms | P95: %.2f ms | Throughput: %.1f decisions/sec",
                    pool_size, mean_ms, median_ms, p95_ms, qps)

        results_by_scale[f"pool_{pool_size}"] = {
            "candidates": pool_size,
            "mean_ms": round(mean_ms, 2),
            "median_ms": round(median_ms, 2),
            "p95_ms": round(p95_ms, 2),
            "min_ms": round(min(latencies_ms), 2),
            "max_ms": round(max(latencies_ms), 2),
            "decisions_per_sec": round(qps, 1),
        }

    mem_end = get_memory_info()
    summary = {
        "model_id": model_id,
        "device": device,
        "cold_load_seconds": round(cold_load_sec, 3),
        "first_inference_ms": round(first_inference_ms, 2),
        "ram_baseline_mb": round(mem_before["ram_mb"], 1),
        "ram_loaded_mb": round(mem_after_load["ram_mb"], 1),
        "ram_delta_mb": round(load_ram_delta, 1),
        "vram_delta_mb": round(load_vram_delta, 1),
        "runs_per_pool": runs,
        "scaling_results": results_by_scale,
    }

    out_file = "laya_benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    logger.info("Saved benchmark results to %s", out_file)
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="convaiinnovations/laya-typed-decisions")
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()

    run_benchmark(model_id=args.model, runs=args.runs, device=args.device)
