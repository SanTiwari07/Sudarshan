"""
Sudarshan Core
==============
The analysis layer shared by both services:

    backend - API gateway, auth, case store, RAG/LLM orchestration
    analysis-engine - containerised APKTool/JADX/Androguard/Frida executor

Why this package exists
-----------------------
These modules previously existed as two byte-identical copies (47 of 48 files,
~11,700 lines each) under ``backend/app/`` and ``analysis-engine/app/``. Nothing
owned them, so every fix had to land twice, the copies had already begun to
drift, and the second copy had no test coverage at all.

Rules for anything added here
-----------------------------
- It must be importable by BOTH services. In particular it must never import
  ``app.db``, ``app.auth``, ``app.ai``, ``app.rag``, ``app.routes`` or
  ``app.workers`` - those exist only in the backend, and an import of one would
  crash the analysis engine at startup. CI enforces this.
- It owns no process-wide state. Both services import it concurrently.
"""

__version__ = "1.0.0"
