# Performance Benchmarks & System Metrics

> [!WARNING]
> **Not verified during the 2026-08-11 documentation audit.** The latency figures, RAM figures, and CPU utilization metrics in this document were recorded during prior benchmarking sessions and have **not** been re-measured in this audit pass. Treat all numeric values as estimates requiring re-verification before use in capacity planning or reports.

## Purpose

This document records the empirical performance benchmarks, processing latencies, resource consumption profiles, and scaling bounds of the **SUDARSHAN** platform components. It provides system administrators and SOC architects with operational capacity planning data.

---

## Responsibilities

This document is responsible for:
1. **Pipeline Latency Benchmarking**: Documenting execution durations across static, dynamic, correlation, risk, and AI processing stages.
2. **Resource Consumption Profiling**: Recording CPU, RAM, and disk IO bounds for backend services.
3. **Scaling Capacity Bounds**: Specifying concurrency bounds for synchronous vs. asynchronous job processing queues.

---

## High-Level Overview

Sudarshan is optimized for low-latency intelligence translation. While traditional reverse engineering requires hours of manual analysis, Sudarshan processes incoming APK binaries in **25 to 55 seconds total pipeline duration**.

```text
[ Analysis Latency Breakdown ]
 Total Pipeline Execution: ~35.0 Seconds Average
 ┌───────────────────────────┬──────────────┬──────────────┬──────────────┐
 │ MobSF / Static Scan       │ Frida AVD    │ Threat Corr. │ Gemini RAG   │
 │ (15.0s - 25.0s)           │ (30.0s)      │ (2.5s)       │ (3.0s)       │
 └───────────────────────────┴──────────────┴──────────────┴──────────────┘
```

---

## Component Performance Benchmarks

Empirical performance metrics measured on reference test hardware (*Intel Core i7-12700K, 32GB RAM, NVMe SSD, Pixel 6 Android 13 AVD*):

| Processing Stage | Service / Module | Average Latency | Peak Latency | RAM Consumption | CPU Usage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **API Ingestion & Hash** | [`upload.py`](../../backend/app/routes/upload.py) | `0.05s` | `0.15s` | `15 MB` | `< 5%` |
| **Native Static Scan** | [`apk_analyzer.py`](../../shared/sudarshan_core/analyzers/apk_analyzer.py) | `1.80s` | `3.50s` | `120 MB` | `25%` |
| **MobSF Container Scan**| [`mobsf_client.py`](../../shared/sudarshan_core/services/mobsf_client.py) | `22.0s` | `45.0s` | `512 MB` | `45%` |
| **Dynamic Execution** | [`frida_sandbox.py`](../../shared/sudarshan_core/engines/frida_sandbox.py) | `30.0s` (Fixed) | `30.0s` | `1.2 GB` (AVD) | `60%` |
| **Threat Correlation** | [`threat_correlator.py`](../../shared/sudarshan_core/services/threat_correlator.py) | `2.20s` | `4.50s` | `25 MB` | `< 5%` |
| **Risk Engine Score** | [`risk_engine.py`](../../shared/sudarshan_core/engines/risk_engine.py) | `0.002s` | `0.005s` | `< 5 MB` | `< 1%` |
| **RAG Evidence Index** | [`gemini_rag.py`](../../backend/app/ai/gemini_rag.py) | `0.10s` | `0.25s` | `10 MB` | `< 5%` |
| **Gemini RAG Synthesis** | [`gemini_client.py`](../../backend/app/ai/gemini_client.py) | `3.20s` | `6.00s` | `15 MB` | `< 5%` |
| **SSE Stream First Token**| `/api/v1/chat/stream` | `0.45s` | `0.80s` | `15 MB` | `< 5%` |

---

## Processing Mode Comparison

Sudarshan supports two operational ingestion modes:

```mermaid
graph TD
    subgraph Synchronous Analysis Mode (/api/v1/analyze)
        A1[Upload APK] --> A2[Execute Full Pipeline 35s] --> A3[Return Complete JSON]
    end

    subgraph Asynchronous Analysis Mode (/api/v1/analyze/async)
        B1[Upload APK] --> B2[Enqueue & Return job_id < 0.2s] --> B3[Background Worker Execution]
    end
```

- **Synchronous Ingestion (`POST /api/v1/analyze`)**:
  - Client blocks until complete analysis finishes.
  - Latency: **$25.0s - 55.0s$** depending on MobSF container load and APK size.
  - Recommended for single-file analyst uploads via Dashboard.
- **Asynchronous Ingestion (`POST /api/v1/analyze/async` with worker queue)**:
  - Immediate HTTP response with job status in **$<0.20$ seconds**.
  - Background worker pool processes queue items asynchronously ([`analysis_queue.py`](../../backend/app/workers/analysis_queue.py)).
  - Recommended for high-volume SIEM/SOAR bulk ingestion.

---

## Memory & Concurrency Bounds

1. **Backend Memory Footprint**:
   - Baseline Idle: `180 MB RAM`.
   - Peak Active (Static + Dynamic + RAG): `450 MB RAM` (excluding MobSF & AVD containers).
2. **MobSF Docker Container Footprint**:
   - Baseline Idle: `350 MB RAM`.
   - Peak Active Scan: `1.1 GB RAM`.
3. **Android Studio AVD Footprint**:
   - Pixel 6 AVD Memory Allocation: `2.0 GB RAM`.
4. **Queue Concurrency Bound**:
   - In-memory worker queue supports up to **10 concurrent jobs** in queue memory ([`analysis_queue.py`](../../backend/app/workers/analysis_queue.py)).
