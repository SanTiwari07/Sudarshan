import asyncio
import aiosqlite

async def q():
    async with aiosqlite.connect("sudarshan.db") as db:
        async with db.execute("SELECT username, role, created_at FROM users") as cursor:
            rows = await cursor.fetchall()
            for row in rows:
                print(f"user={row[0]} role={row[1]} created={row[2]}")

asyncio.run(q())
