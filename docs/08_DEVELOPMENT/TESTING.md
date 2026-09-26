# SUDARSHAN — Testing Framework & Test Suite Guide

> **Classification:** AUTHORITATIVE  
> **Total Verified Tests:** 2,841 collected tests  

---

## 1. Running the Test Suite

Run unit and backend tests using the virtual environment:
```bash
# Run backend test suite
$env:JWT_SECRET_KEY="test_key_for_testing_123456789012345678901234567890"
.venv\Scripts\python -m pytest backend/tests -v

# Run shared core & engine unit tests
.venv\Scripts\python -m pytest tests/unit -v

# Run full repository test suite
.venv\Scripts\python -m pytest tests/unit backend/tests -q
```

---

## 2. Test Architecture

- **Unit Tests (`tests/unit/`):** Mocked sandbox providers, deterministic risk verification, VIDE AST comparison, and evidence serialization. No live emulator required.
- **Backend Tests (`backend/tests/`):** FastAPI HTTP client tests, authentication token flows, database transactions, RBAC permissions, and route boundary tests.
- **Integration Tests (`tests/integration/`):** End-to-end pipeline validation requiring a running emulator and Docker containers.
