# SUDARSHAN — Codebase Map & Directory Guide

> **Classification:** AUTHORITATIVE  
> **Last Verified:** 2026-09-25  

---

## 1. High-Level Directory Layout

```
C:\Projects\Sudarshan\
├── backend/               # FastAPI Gateway, case store, auth, workers, and RAG
├── analysis-engine/       # Containerized analysis microservice (APKTool, JADX, Frida, ADB)
├── shared/                # sudarshan_core: risk engine, VIDE, Frida hooks, schemas
├── frontend/              # React 18 / Vite 5 / TailwindCSS analyst dashboard
├── tests/                 # Unit and integration test suite (1,970 tests)
├── scripts/               # Operator tooling, setup scripts, and admin utilities
├── deploy/                # Deployment configurations and Dockerfiles
├── docs/                  # Unified documentation portal
├── docker-compose.yml     # Standard service stack definition
├── start.ps1              # Windows one-command startup orchestrator
└── pytest.ini             # Test configuration (asyncio_mode = auto)
```

---

## 2. Detailed Component Directory Trees

### 2.1 Backend (`backend/`)
```
backend/
├── app/
│   ├── ai/                # Gemini RAG client, prompt templates, investigation graph
│   ├── auth/              # JWT token issuance, password hashing, RBAC middleware
│   ├── db/                # Database migrations, raw SQL repository, connection pool
│   ├── middleware/        # Security headers, rate limiting, audit logging
│   ├── models/            # Pydantic schemas for API requests/responses
│   ├── rag/               # Vector knowledge base and indexing
│   ├── routes/            # FastAPI route controllers:
│   │   ├── auth.py        # /api/v1/auth
│   │   ├── upload.py      # /api/v1/upload, /api/v1/analyze
│   │   ├── cases.py       # /api/v1/cases
│   │   ├── batch.py       # /api/v1/batch
│   │   ├── discovery.py   # /api/v1/discovery
│   │   ├── report.py      # /api/v1/report
│   │   ├── intelligence.py# /api/v1/intelligence
│   │   ├── resilience.py  # /api/v1/resilience
│   │   └── audit.py       # /api/v1/audit
│   ├── services/          # Audit logging, case management, threat correlation
│   ├── workers/           # Background async analysis queue & batch workers
│   └── main.py            # Gateway entrypoint (FastAPI v2.1.0)
└── tests/                 # 871 automated tests across 67 test files
```

### 2.2 Analysis Engine (`analysis-engine/`)
```
analysis-engine/
├── app/
│   └── main.py            # Microservice entrypoint (FastAPI v2.3.0, port 8001)
├── Dockerfile             # Ubuntu 24.04, Java 17, Python 3.12, APKTool, JADX
└── entrypoint.sh          # Container health check and uvicorn launcher
```

### 2.3 Shared Core (`shared/sudarshan_core/`)
```
shared/sudarshan_core/
├── ai/                    # Gemini provider, circuit breaker, settings
├── analyzers/             # Native Androguard APK analyzer
├── brand/                 # Institutional logos and branding assets
├── config/                # Platform configuration and environment settings
├── data/                  # Bank signer registry (bank_signer_registry.json)
├── engines/
│   ├── agentic/           # Deep UI explorer, semantic classifier, goal planner
│   ├── frida_hooks/       # Compiled Frida JavaScript instrumentation bundles
│   ├── vide/              # Visual Impersonation Detection Engine
│   ├── apk_repair.py      # Corrupted APK & AXML reconstructor
│   ├── apktool_engine.py  # Subprocess wrapper for APKTool 2.10.0
│   ├── jadx_engine.py     # Subprocess wrapper for JADX 1.5.1
│   ├── frida_sandbox.py   # Frida session lifecycle & PID attachment
│   ├── bfci_scorer.py     # Behavioral Fraud Confidence Index (BFCI v2)
│   ├── risk_engine.py     # Deterministic Risk Engine (STEI, FRS, Triad)
│   ├── yara_scanner.py    # Runtime YARA scanner for trojan strings
│   ├── event_bus.py       # In-memory pub/sub telemetry event bus
│   └── screenshot_manager.py # PII-sanitized screenshot capture
├── models/                # Investigation manifest and data contracts
├── sandbox/               # ADB providers (Genymotion, Android Studio, Auto)
├── security/              # Internal auth tokens and sandbox containment
├── services/              # MobSF client, external threat correlator (VT/OTX)
└── storage/               # Artifact storage abstraction (Local/S3/GCS)
```

### 2.4 Frontend (`frontend/`)
```
frontend/
├── src/
│   ├── components/        # Reusable UI widgets (cards, badges, modal, timeline)
│   ├── context/           # React context providers (Auth, Case selection)
│   ├── hooks/             # Custom hooks (useAnalysis, useWebSocket, useAuth)
│   ├── layout/            # AppShell, Sidebar, Header, Navigation
│   ├── pages/             # Route views:
│   │   ├── FraudCard.tsx  # Executive fraud summary card
│   │   ├── TechnicalView.tsx # In-depth SOC analyst telemetry viewer
│   │   ├── ThreatIntelView.tsx # External threat intelligence overview
│   │   ├── BatchScan.tsx  # Multi-file batch upload & queue status
│   │   ├── BatchDetail.tsx# Detailed batch progress and metrics
│   │   ├── InvestigationChat.tsx # RAG AI investigation assistant
│   │   ├── Discovery.tsx  # APK crawler and discovery ingestion
│   │   ├── History.tsx    # Case search and history
│   │   ├── Settings.tsx   # Platform configuration & keys
│   │   └── Login.tsx      # Analyst authentication
│   └── types/             # TypeScript data contracts and API types
├── package.json           # React 18, Vite 5, TailwindCSS dependencies
└── vite.config.ts         # Vite build configuration with proxy rules
```
