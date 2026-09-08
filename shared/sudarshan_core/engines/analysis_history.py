"""
SUDARSHAN - Analysis History
=============================
DEPRECATED. Analysis history is now owned by the gateway.

What this used to do, and why it was replaced
---------------------------------------------
It opened `sudarshan.db` **relative to the process CWD**. The sandbox runs with
WORKDIR=/app inside the analysis-engine container, so it created a third,
independent database at `analysis-engine/sudarshan.db` that shared nothing with
the gateway's - and that nothing ever read.

The rows were unusable regardless. The one call site passed a literal:

    history.save_run(result, apk_sha256="unknown", stage_name="single")

and `save_run` hardcoded five more columns to empty before inserting. Across
the three database files, all 140 rows carry apk_sha256='unknown' and
bfci_score=0.0, so `compare_runs` computed `0.0 - 0.0` on every call. Nothing
invoked it.

It also used synchronous `sqlite3` from the async analysis pipeline, with no
`busy_timeout` - so it blocked the event loop and would raise
"database is locked" under contention rather than waiting.

Replacement
-----------
    backend/app/services/run_recorder.py   maps a real result onto real columns
    backend/app/db/intel.py                async accessors + compare_runs()

`analysis_runs` now lives in the gateway database with the rest of the
application's state, and the historical rows are preserved and flagged
`is_placeholder = 1` (migration 0006) so they are excluded from comparisons
instead of being deleted or, worse, treated as measurements.

This class is kept as a no-op shim so that any caller still importing it does
not crash. It writes nothing.
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

class AnalysisHistory:
    """No-op shim. See the module docstring - the real implementation moved."""

    def __init__(self, db_path: str = "sudarshan.db"):
        self.db_path = db_path
        logger.debug(
            "[AnalysisHistory] deprecated shim instantiated; analysis history is "
            "recorded by the gateway (app.services.run_recorder)."
        )

    def _init_db(self) -> None:
        """Deliberately empty - creating the table here is what produced the
        stray analysis-engine/sudarshan.db."""

    def save_run(
        self,
        result: Dict[str, Any],
        apk_sha256: str = "unknown",
        stage_name: str = "single",
        explorer_mode: str = "ai",
    ) -> bool:
        """
        Does nothing and reports it.

        Returning True would tell the caller a run was recorded when none was.
        The gateway records the run from the analysis result it receives back,
        where the real sha256, FRS, STEI and BFCI are all available - none of
        which this code path ever had.
        """
        logger.debug(
            "[AnalysisHistory] save_run() ignored for %s - the gateway records "
            "analysis history now.",
            result.get("package_name", "unknown"),
        )
        return False

    def compare_runs(self, package_name: str, limit: int = 5) -> Dict[str, Any]:
        """Use app.db.intel.compare_runs, which compares real scores."""
        return {
            "status": "moved",
            "message": (
                "Analysis history moved to the gateway database. "
                "Use app.db.intel.compare_runs()."
            ),
        }
