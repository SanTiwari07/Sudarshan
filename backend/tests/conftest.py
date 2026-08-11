"""Pytest hooks for backend/tests (fixture modules live alongside tests)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
