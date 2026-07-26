"""
SUDARSHAN — Analysis History
=============================
Maintains a SQLite database of all analysis runs for trending and historical comparison.
"""

import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class AnalysisHistory:
    def __init__(self, db_path: str = "sudarshan.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS analysis_runs (
                        id               INTEGER PRIMARY KEY AUTOINCREMENT,
                        package_name     TEXT    NOT NULL,
                        apk_sha256       TEXT    NOT NULL,
                        run_timestamp    TEXT    NOT NULL,
                        stage_name       TEXT    DEFAULT 'single',
                        duration_seconds INTEGER,
                        bfci_score       REAL,
                        bfci_components  TEXT,   -- JSON
                        mitre_techniques TEXT,   -- JSON array of technique IDs
                        ioc_count        INTEGER DEFAULT 0,
                        screenshot_count INTEGER DEFAULT 0,
                        yara_matches     TEXT,   -- JSON
                        anti_analysis    TEXT,   -- JSON
                        explorer_mode    TEXT
                    )
                ''')
                conn.commit()
        except Exception as e:
            logger.error(f"[AnalysisHistory] DB init failed: {e}")

    def save_run(self, result: Dict[str, Any], apk_sha256: str = "unknown", stage_name: str = "single", explorer_mode: str = "ai") -> bool:
        """Save a complete run result to the database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Extract fields safely
                package_name = result.get("package_name", "unknown")
                bfci = result.get("bfci", 0.0)
                duration = result.get("duration_seconds", 0)
                
                components = json.dumps(result.get("bfci_components", {}))
                
                # Mitre is handled separately, but we might have a summary in the result if passed in later
                mitre_techs = "[]" 
                ioc_count = 0
                yara_matches = "[]"
                anti_analysis = "[]"
                screenshot_count = 0
                
                run_ts = datetime.now(tz=timezone.utc).isoformat()
                
                cursor.execute('''
                    INSERT INTO analysis_runs (
                        package_name, apk_sha256, run_timestamp, stage_name,
                        duration_seconds, bfci_score, bfci_components,
                        mitre_techniques, ioc_count, screenshot_count,
                        yara_matches, anti_analysis, explorer_mode
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    package_name, apk_sha256, run_ts, stage_name,
                    duration, bfci, components,
                    mitre_techs, ioc_count, screenshot_count,
                    yara_matches, anti_analysis, explorer_mode
                ))
                conn.commit()
                logger.info(f"[AnalysisHistory] Saved run for {package_name} (BFCI: {bfci})")
                return True
        except Exception as e:
            logger.error(f"[AnalysisHistory] Failed to save run: {e}")
            return False

    def compare_runs(self, package_name: str, limit: int = 5) -> Dict[str, Any]:
        """Compare the most recent run with previous runs for the same package."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM analysis_runs 
                    WHERE package_name = ? 
                    ORDER BY run_timestamp DESC 
                    LIMIT ?
                ''', (package_name, limit))
                
                rows = cursor.fetchall()
                
                if not rows or len(rows) < 2:
                    return {"status": "insufficient_data"}
                    
                latest = rows[0]
                previous = rows[1]
                
                # Basic comparison
                bfci_delta = latest["bfci_score"] - previous["bfci_score"]
                
                return {
                    "status": "success",
                    "package": package_name,
                    "latest_run": latest["run_timestamp"],
                    "previous_run": previous["run_timestamp"],
                    "bfci_delta": bfci_delta,
                    "latest_score": latest["bfci_score"],
                    "previous_score": previous["bfci_score"]
                }
        except Exception as e:
            logger.error(f"[AnalysisHistory] Compare failed: {e}")
            return {"status": "error", "message": str(e)}
