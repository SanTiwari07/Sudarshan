# Duplicate Code Audit Report

## Identified Duplicates

### Duplicate File Pair
- **FILE A**: `C:\Projects\Sudarshan\scripts\write_stage_b.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\write_summary.py`
- **FUNCTION / CLASS**: Whole File
- **PURPOSE**: Exact file duplicates found.
- **CALLERS**: Requires investigation
- **IMPORTERS**: Requires investigation
- **RUNTIME USE**: Same
- **TEST USE**: Same
- **CANONICAL IMPLEMENTATION**: Neither
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `convert_qmark_to_dollar`
- **FILE A**: `C:\Projects\Sudarshan\backend\test_converter.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\app\db\pool.py`
- **FUNCTION / CLASS**: Function `convert_qmark_to_dollar`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\test_converter.py` (assumed)
- **RECOMMENDATION**: MERGE

### Duplicate Function: `_to_str_list`
- **FILE A**: `C:\Projects\Sudarshan\backend\app\ai\gemini_client.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\app\routes\upload.py`
- **FUNCTION / CLASS**: Function `_to_str_list`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\app\ai\gemini_client.py` (assumed)
- **RECOMMENDATION**: MERGE

### Duplicate Function: `create_indexes`
- **FILE A**: `C:\Projects\Sudarshan\backend\app\db\intel.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\app\db\security.py`
- **FUNCTION / CLASS**: Function `create_indexes`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\app\db\intel.py` (assumed)
- **RECOMMENDATION**: MERGE

### Duplicate Function: `_now`
- **FILE A**: `C:\Projects\Sudarshan\backend\app\db\intel.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\app\db\security.py`
- **FUNCTION / CLASS**: Function `_now`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\app\db\intel.py` (assumed)
- **RECOMMENDATION**: MERGE

### Duplicate Function: `__aexit__`
- **FILE A**: `C:\Projects\Sudarshan\backend\app\db\pool.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\tests\test_analysis_client.py`
- **FUNCTION / CLASS**: Function `__aexit__`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\app\db\pool.py` (assumed)
- **RECOMMENDATION**: MERGE

### Duplicate Function: `_fetchall`
- **FILE A**: `C:\Projects\Sudarshan\backend\app\db\pool.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\app\db\pool.py`
- **FUNCTION / CLASS**: Function `_fetchall`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\app\db\pool.py` (assumed)
- **RECOMMENDATION**: MERGE

### Duplicate Function: `_now_iso`
- **FILE A**: `C:\Projects\Sudarshan\backend\app\routes\batch.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\app\workers\batch_worker.py`
- **FUNCTION / CLASS**: Function `_now_iso`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\app\routes\batch.py` (assumed)
- **RECOMMENDATION**: MERGE

### Duplicate Function: `_flags_to_dict`
- **FILE A**: `C:\Projects\Sudarshan\backend\app\routes\upload.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\validation\static_scoring.py`
- **FUNCTION / CLASS**: Function `_flags_to_dict`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\app\routes\upload.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `check_root`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_anti_evasion_api.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_anti_evasion.py`
- **FUNCTION / CLASS**: Function `check_root`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_anti_evasion_api.py` (assumed)
- **RECOMMENDATION**: MERGE (Extract to shared test_utils)

### Duplicate Function: `_make_ui_node`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_boundary_exploration.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\tests\test_deep_exploration_regression.py`
- **FUNCTION / CLASS**: Function `_make_ui_node`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_boundary_exploration.py` (assumed)
- **RECOMMENDATION**: MERGE (Extract to shared test_utils)

### Duplicate Function: `_make_obs`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_boundary_exploration.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\tests\test_deep_exploration_regression.py`
- **FUNCTION / CLASS**: Function `_make_obs`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_boundary_exploration.py` (assumed)
- **RECOMMENDATION**: MERGE (Extract to shared test_utils)

### Duplicate Function: `create_valid_apk`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\verify_url_ingestion.py`
- **FUNCTION / CLASS**: Function `create_valid_apk`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `handle_valid_apk`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\verify_url_ingestion.py`
- **FUNCTION / CLASS**: Function `handle_valid_apk`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `handle_redirect`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\verify_url_ingestion.py`
- **FUNCTION / CLASS**: Function `handle_redirect`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `handle_redirect_loop`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\verify_url_ingestion.py`
- **FUNCTION / CLASS**: Function `handle_redirect_loop`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `handle_html`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\verify_url_ingestion.py`
- **FUNCTION / CLASS**: Function `handle_html`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `handle_large`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\verify_url_ingestion.py`
- **FUNCTION / CLASS**: Function `handle_large`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `start_server`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\verify_url_ingestion.py`
- **FUNCTION / CLASS**: Function `start_server`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `large_stream`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\verify_url_ingestion.py`
- **FUNCTION / CLASS**: Function `large_stream`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_url_ingestion.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `_write_png`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_visual_evidence_linker.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_evidence_provenance.py`
- **FUNCTION / CLASS**: Function `_write_png`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_visual_evidence_linker.py` (assumed)
- **RECOMMENDATION**: MERGE (Extract to shared test_utils)

### Duplicate Function: `_manifest_entry`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_visual_evidence_linker.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_evidence_provenance.py`
- **FUNCTION / CLASS**: Function `_manifest_entry`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_visual_evidence_linker.py` (assumed)
- **RECOMMENDATION**: MERGE (Extract to shared test_utils)

### Duplicate Function: `adb`
- **FILE A**: `C:\Projects\Sudarshan\scripts\bisect_sections.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\bisect_spawn_hooks.py`
- **FUNCTION / CLASS**: Function `adb`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\bisect_sections.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `ensure_frida_server`
- **FILE A**: `C:\Projects\Sudarshan\scripts\bisect_sections.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\bisect_spawn_hooks.py`
- **FUNCTION / CLASS**: Function `ensure_frida_server`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\bisect_sections.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `get_device`
- **FILE A**: `C:\Projects\Sudarshan\scripts\bisect_sections.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\bisect_spawn_hooks.py`
- **FUNCTION / CLASS**: Function `get_device`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\bisect_sections.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `force_stop`
- **FILE A**: `C:\Projects\Sudarshan\scripts\bisect_sections.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\bisect_spawn_hooks.py`
- **FUNCTION / CLASS**: Function `force_stop`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\bisect_sections.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `get_pid`
- **FILE A**: `C:\Projects\Sudarshan\scripts\bisect_sections.py`
- **FILE B**: `C:\Projects\Sudarshan\scripts\bisect_spawn_hooks.py`
- **FUNCTION / CLASS**: Function `get_pid`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\bisect_sections.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `_ok`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_fallback.py`
- **FUNCTION / CLASS**: Function `_ok`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `_settings`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_fallback.py`
- **FUNCTION / CLASS**: Function `_settings`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `__init__`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_fallback.py`
- **FUNCTION / CLASS**: Function `__init__`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `__init__`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_fallback.py`
- **FUNCTION / CLASS**: Function `__init__`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `generate_content`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_fallback.py`
- **FUNCTION / CLASS**: Function `generate_content`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `generate_content_stream`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_provider.py`
- **FUNCTION / CLASS**: Function `generate_content_stream`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `__init__`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_provider.py`
- **FUNCTION / CLASS**: Function `__init__`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `factory`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_provider.py`
- **FUNCTION / CLASS**: Function `factory`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `worker`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_fallback.py`
- **FUNCTION / CLASS**: Function `worker`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `_get_provider`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\anti_evasion.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\device_state_simulator.py`
- **FUNCTION / CLASS**: Function `_get_provider`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\anti_evasion.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `api_level`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\device_state_simulator.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\time_warp.py`
- **FUNCTION / CLASS**: Function `api_level`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\device_state_simulator.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `_utcnow`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\agent_memory.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\audit_log.py`
- **FUNCTION / CLASS**: Function `_utcnow`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\agent_memory.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `to_dict`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\agent_memory.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\exploration_engine.py`
- **FUNCTION / CLASS**: Function `to_dict`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\agent_memory.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `invalidate_cache_for_screen`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\decision_provider.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\decision_provider.py`
- **FUNCTION / CLASS**: Function `invalidate_cache_for_screen`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\decision_provider.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `decide`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\decision_provider.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\decision_provider.py`
- **FUNCTION / CLASS**: Function `decide`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\decision_provider.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `invalidate_cache_for_screen`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\decision_provider.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\decision_provider.py`
- **FUNCTION / CLASS**: Function `invalidate_cache_for_screen`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\decision_provider.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `is_complete`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\goal_planner.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\goal_planner.py`
- **FUNCTION / CLASS**: Function `is_complete`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\goal_planner.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `_channel`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\perception.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\tool_executor.py`
- **FUNCTION / CLASS**: Function `_channel`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\engines\agentic\perception.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `shell`
- **FILE A**: `C:\Projects\Sudarshan\shared\sudarshan_core\sandbox\android_studio.py`
- **FILE B**: `C:\Projects\Sudarshan\shared\sudarshan_core\sandbox\auto.py`
- **FUNCTION / CLASS**: Function `shell`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\shared\sudarshan_core\sandbox\android_studio.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Function: `exploding`
- **FILE A**: `C:\Projects\Sudarshan\tests\unit\test_action_verifier.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_action_verifier.py`
- **FUNCTION / CLASS**: Function `exploding`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\tests\unit\test_action_verifier.py` (assumed)
- **RECOMMENDATION**: MERGE (Extract to shared test_utils)

### Duplicate Function: `fake_adb`
- **FILE A**: `C:\Projects\Sudarshan\tests\unit\test_sandbox_provider.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_sandbox_provider.py`
- **FUNCTION / CLASS**: Function `fake_adb`
- **PURPOSE**: Identical function implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\tests\unit\test_sandbox_provider.py` (assumed)
- **RECOMMENDATION**: MERGE (Extract to shared test_utils)

### Duplicate Class: `_Req`
- **FILE A**: `C:\Projects\Sudarshan\backend\tests\test_persistence_layer.py`
- **FILE B**: `C:\Projects\Sudarshan\backend\tests\test_persistence_layer.py`
- **FUNCTION / CLASS**: Class `_Req`
- **PURPOSE**: Identical class implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\backend\tests\test_persistence_layer.py` (assumed)
- **RECOMMENDATION**: MERGE (Extract to shared test_utils)

### Duplicate Class: `FakeHTTPError`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_fallback.py`
- **FUNCTION / CLASS**: Class `FakeHTTPError`
- **PURPOSE**: Identical class implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Class: `FakeModels`
- **FILE A**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_gemini_provider.py`
- **FUNCTION / CLASS**: Class `FakeModels`
- **PURPOSE**: Identical class implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\scripts\test_gemini_api_fallback.py` (assumed)
- **RECOMMENDATION**: REQUIRES REVIEW

### Duplicate Class: `D`
- **FILE A**: `C:\Projects\Sudarshan\tests\unit\test_blocker_fixes.py`
- **FILE B**: `C:\Projects\Sudarshan\tests\unit\test_blocker_fixes.py`
- **FUNCTION / CLASS**: Class `D`
- **PURPOSE**: Identical class implementation
- **CALLERS**: Multiple
- **IMPORTERS**: Multiple
- **RUNTIME USE**: Varies
- **TEST USE**: Varies
- **CANONICAL IMPLEMENTATION**: `C:\Projects\Sudarshan\tests\unit\test_blocker_fixes.py` (assumed)
- **RECOMMENDATION**: MERGE (Extract to shared test_utils)
