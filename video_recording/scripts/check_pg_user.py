import asyncio
from app.db import pool
from app.auth.auth import verify_password

async def test():
    async with pool.connect() as db:
        r = await (await db.execute('SELECT * FROM users WHERE username = $1', ('admin',))).fetchone()
        print('Postgres admin user:', dict(r))
        v = verify_password('Admin123!', r['hashed_pw'])
        print('Password verifies against Postgres user:', v)

asyncio.run(test())
