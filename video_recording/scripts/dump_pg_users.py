import asyncio
from app.db import pool

async def dump_pg():
    async with pool.connect() as db:
        rows = await (await db.execute('SELECT id, username, hashed_pw FROM users')).fetchall()
        print('Postgres users:')
        for r in rows:
            print(r['id'], r['username'], repr(r['hashed_pw']))

asyncio.run(dump_pg())
