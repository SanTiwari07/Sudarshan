import asyncio
import aiosqlite
from passlib.context import CryptContext

async def reset():
    pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
    h = pwd.hash("Sudarshan@2026")
    async with aiosqlite.connect("sudarshan.db") as db:
        async with db.execute("SELECT id, username, role FROM users") as c:
            rows = await c.fetchall()
        for r in rows:
            print(f"  user id={r[0]} username={r[1]} role={r[2]}")
        await db.execute("UPDATE users SET hashed_pw=? WHERE username=?", (h, "admin"))
        await db.commit()
        print("Password reset to: Sudarshan@2026")

asyncio.run(reset())
