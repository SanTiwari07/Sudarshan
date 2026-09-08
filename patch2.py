import sys

with open('backend/app/routes/runtime_api.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace list(_ACTIVE_TRACKERS.values()) with await _filter_trackers(current_user, list(_ACTIVE_TRACKERS.values())) in multiple places
content = content.replace('active_trackers = list(_ACTIVE_TRACKERS.values())', 'active_trackers = await _filter_trackers(current_user, list(_ACTIVE_TRACKERS.values()))')
content = content.replace('trackers = list(_ACTIVE_TRACKERS.values())', 'trackers = await _filter_trackers(current_user, list(_ACTIVE_TRACKERS.values()))')

# Replace _recent_events with await _filter_events(current_user, list(reversed(_recent_events)))
content = content.replace('events = list(reversed(_recent_events))  # most recent first', 'events = await _filter_events(current_user, list(reversed(_recent_events)))')

# Add access check for endpoints that take case_id directly and do not rely purely on trackers filtering
# Actually _load_evidence_from_artifacts doesn't filter, so we should filter runtime_evidence
def inject_check(func_name):
    global content
    find_str = f"def {func_name}("
    idx = content.find(find_str)
    if idx != -1:
        idx_colon = content.find("):", idx)
        if idx_colon != -1:
            idx_start = content.find("\n", idx_colon) + 1
            idx_doc = content.find('"""', idx_start)
            if idx_doc != -1:
                idx_end = content.find('"""', idx_doc + 3) + 4
                content = content[:idx_end] + "\n    await _check_case_access(current_user, case_id)\n" + content[idx_end:]

inject_check("runtime_hooks")
inject_check("runtime_pipeline")
inject_check("runtime_evidence")
inject_check("runtime_diagnostics")

# Special case for hooks global registry
# If scope is not None, do not return _hook_registry
idx = content.find('hooks_out: Dict[str, Any] = {}')
if idx != -1:
    idx = content.find('\n', idx) + 1
    content = content[:idx] + '''    scope = list_scope_analyst_id(current_user)
    if scope is None:
        for name, info in _hook_registry.items():
            hooks_out[name] = {
                "installed": info["installed"],
                "fired": info["fired"],
                "errors": info["errors"],
                "last_fired_ts": info.get("last_fired_ts"),
            }
''' + content[idx:]
    # Remove the original loop
    content = content.replace('''    # From module registry
    for name, info in _hook_registry.items():
        hooks_out[name] = {
            "installed": info["installed"],
            "fired": info["fired"],
            "errors": info["errors"],
            "last_fired_ts": info.get("last_fired_ts"),
        }''', '    # Module registry merged above conditionally')


with open('backend/app/routes/runtime_api.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Applied filters')
