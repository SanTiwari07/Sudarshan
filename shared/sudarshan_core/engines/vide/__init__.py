"""Visual Impersonation Detection Engine (VIDE)."""

from sudarshan_core.engines.vide.pipeline import run_vide_analysis, safe_run_vide_analysis
from sudarshan_core.engines.vide.ui_profile import UIProfile, VIDECompareResult

__all__ = ["run_vide_analysis", "safe_run_vide_analysis", "UIProfile", "VIDECompareResult"]
