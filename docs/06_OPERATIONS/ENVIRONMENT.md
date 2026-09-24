# SUDARSHAN — Environment Variables & Configuration

> **Classification:** AUTHORITATIVE  

---

## Core Variables Matrix

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `SUDARSHAN_ENV` | `development` | Deployment environment (`development` or `production`). |
| `JWT_SECRET_KEY` | *None (Mandatory)* | Secret key for signing authentication tokens. Refuses to start if empty. |
| `DATABASE_URL` | `postgresql://...` | Connection string for database. Falls back to SQLite if unset. |
| `SUDARSHAN_DB_PATH` | `/app/data/sudarshan.db` | Explicit path for SQLite database file. |
| `ANALYSIS_ENGINE_URL` | `http://analysis-engine:8001`| Internal URL for the analysis engine microservice. |
| `ANALYSIS_ENGINE_INTERNAL_TOKEN` | *None* | Shared secret for inter-service communication. |
| `GEMINI_API_KEY` | *Optional* | Google Gemini API key for RAG investigation chat. |
| `GEMINI_MODEL` | `gemini-2.5-flash` | LLM model identifier. |
| `VIRUSTOTAL_API_KEY` | *Optional* | API key for VirusTotal reputation queries. |
| `OTX_API_KEY` | *Optional* | API key for AlienVault OTX pulses. |
| `ABUSEIPDB_API_KEY` | *Optional* | API key for AbuseIPDB IP reputation lookups. |
| `FRIDA_ANALYSIS_DURATION` | `130` | Seconds to run dynamic Frida instrumentation per sample. |
