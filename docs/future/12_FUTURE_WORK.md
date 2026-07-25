# 12 — Future Work & Architectural Roadmap

## Purpose

This document details the planned research roadmap, architectural refinements, and infrastructure upgrades for future iterations of the **SUDARSHAN** platform. It outlines strategic engineering initiatives designed to overcome current dynamic instrumentation constraints, expand queue scalability, and transition to kernel-level telemetry.

---

## Responsibilities

This document is responsible for:
1. **Documenting Future Roadmap Initiatives**: Articulating documented technical enhancements across telemetry, queueing, containerization, and vector search.
2. **Architectural Specification**: Providing technical design blueprints for eBPF kernel monitoring, Celery worker migration, and Cuttlefish AVD orchestration.
3. **Research Guidance**: Guiding future contributors and maintainers on approved architectural directions.

---

## High-Level Overview

Future development focuses on advancing from user-space application hooking to unbypassable kernel-level monitoring while upgrading system throughput for high-concurrency enterprise banking deployments:

```text
[ Current Baseline Platform ]
- User-Space Frida Instrumentation
- In-Memory Python Async Queue
- Local Android Studio AVD
- In-Memory RAG Evidence Index
                 │
                 ▼
[ Target Future Platform Architecture ]
- eBPF Kernel-Space Telemetry Floor (Cuttlefish AVD)
- Redis + Celery Distributed Worker Cluster
- Cloud-Native Cuttlefish AVD Fleet in Kubernetes
- Persistent Local Vector Database (ChromaDB / FAISS)
```

---

## Technical Enhancements & Blueprints

### 1. eBPF Kernel-Space Telemetry Floor
*Refinement for Dynamic Analysis Reliability*
- **Problem**: Modern Android runtimes (ART) aggressively inline methods, while sophisticated banking trojans detect user-space Frida ptrace attachment and crash or alter behavior.
- **Solution Blueprint**: Replace user-space Frida instrumentation with kernel-level eBPF (Extended Berkeley Packet Filter) tracepoints on Cuttlefish Android instances.
- **Architecture**:
  ```mermaid
  graph TD
      subgraph Cuttlefish Android Kernel
          SYS[System Call Interface]
          EBPF[eBPF Kernel Probes<br/>sys_enter_openat, sys_enter_socket]
          RING[eBPF Ring Buffer]
      end

      subgraph Sudarshan Telemetry Daemon
          AGENT[eBPF Event Collector]
          STORE[EvidenceStore]
      end

      SYS --> EBPF
      EBPF --> RING
      RING --> AGENT
      AGENT --> STORE
  ```
- **Benefits**: Completely invisible to user-space anti-analysis checks; immune to ART method inlining; captures 100% of socket, file, and process operations.

---

### 2. Distributed Celery + Redis Worker Cluster
*Refinement for Queue Scalability*
- **Problem**: The current `analysis_queue.py` operates within FastAPI process memory, restricting worker execution to a single node instance.
- **Solution Blueprint**: Migrate job dispatching to a Redis-backed Celery distributed task queue.
- **Architecture**:
  ```mermaid
  graph TD
      API[FastAPI Gateway Node] --> REDIS[(Redis Task Broker)]
      REDIS --> W1[Worker Node 1]
      REDIS --> W2[Worker Node 2]
      REDIS --> W3[Worker Node N]

      W1 --> DB[(PostgreSQL Store)]
      W2 --> DB
      W3 --> DB
  ```

---

### 3. Cuttlefish AVD Fleet in Kubernetes
*Refinement for Cloud-Native Dynamic Sandboxing*
- **Problem**: Local Android Studio AVDs require GUI environments and dedicated host GPU pass-through, hindering headless cloud deployment.
- **Solution Blueprint**: Deploy Google Cuttlefish Android instances inside Kubernetes pods using nested virtualization (`/dev/kvm`).

---

### 4. Persistent Vector Database RAG Integration
*Refinement for Multi-Case Campaign Discovery*
- **Problem**: In-memory `_investigation_index` (`gemini_rag.py`) clears upon backend restart and supports single-case query context only.
- **Solution Blueprint**: Integrate a local vector database (ChromaDB or FAISS) to persist chunk embeddings across all historical cases, enabling cross-case campaign queries (e.g., *"Which other cases shared this C2 IP address?"*).

---

## Roadmap Implementation Matrix

| Enhancement Initiative | Target Layer | Priority | Status |
| :--- | :--- | :--- | :--- |
| **eBPF Kernel Telemetry** | Dynamic Analysis Engine | High | **Planned** |
| **Redis / Celery Queue** | API Gateway & Queue | High | **Planned** |
| **ChromaDB Vector RAG** | AI Investigation Engine | Medium | **Planned** |
| **Cuttlefish K8s Fleet** | Infrastructure & DevOps | Medium | **Planned** |
| **Custom Rule DSL** | Risk Engine | Low | **Planned** |

---

## Current Implementation Status

All roadmap initiatives detailed in this document represent **Planned** enhancements. Current operational state remains accurately documented in `docs/README.md` and `docs/DAE_CURRENT_STATE.md`.
