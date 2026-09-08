import sys

with open('backend/app/routes/runtime_api.py', 'r', encoding='utf-8') as f:
    content = f.read()

helpers = '''
async def _filter_trackers(user: dict, trackers: list) -> list:
    scope = list_scope_analyst_id(user)
    if scope is None:
        return trackers
    allowed = []
    for t in trackers:
        if not t.case_id:
            continue
        row = await get_case(t.case_id)
        if row and row.get("analyst_id") == scope:
            allowed.append(t)
    return allowed

async def _filter_events(user: dict, events: list) -> list:
    scope = list_scope_analyst_id(user)
    if scope is None:
        return events
    allowed = []
    for e in events:
        case_id = e.get("case_id")
        if not case_id:
            continue
        row = await get_case(case_id)
        if row and row.get("analyst_id") == scope:
            allowed.append(e)
    return allowed

async def _check_case_access(user: dict, case_id: str) -> None:
    if not case_id:
        return
    scope = list_scope_analyst_id(user)
    if scope is None:
        return
    row = await get_case(case_id)
    if row and row.get("analyst_id") != scope:
        raise HTTPException(status_code=404, detail="Case not found.")

'''

idx = content.find('router = APIRouter()')
if idx != -1:
    idx = content.find('\n', idx) + 1
    content = content[:idx] + helpers + content[idx:]
    with open('backend/app/routes/runtime_api.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print('Injected helpers')
else:
    print('Could not inject')
