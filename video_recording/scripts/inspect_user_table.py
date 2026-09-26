import asyncio
from app.db import pool

async def inspect():
    async with pool.connect() as db:
        schemas = await (await db.execute(
            "SELECT table_schema, table_name FROM information_schema.tables WHERE table_name = 'users'"
        )).fetchall()
        print('Postgres schemas for table users:')
        for s in schemas:
            print(dict(s))
            
        # Also query with pool.connect() vs database.get_user_by_username
        from app.db.database import get_user_by_username
        u = await get_user_by_username('admin')
        print('get_user_by_username result:')
        print(u)

asyncio.run(inspect())
