import asyncio
from app.db.database import get_user_by_username
from app.db.paths import resolve_db_path

async def test():
    print('resolve_db_path():', resolve_db_path())
    u = await get_user_by_username('admin')
    print('get_user_by_username result:')
    print(u)

asyncio.run(test())
