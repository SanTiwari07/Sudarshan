#!/usr/bin/env python3
"""
Reset admin password in backend SQLite database.
Connects to the SQLite DB file on the host filesystem (from bind mount).
"""
import asyncio
import sys
import os

sys.path.insert(0, r"d:\Projects\Sudarshan BOI\backend")
sys.path.insert(0, r"d:\Projects\Sudarshan BOI\shared")

os.environ["JWT_SECRET_KEY"] = "sudarshan_secret_jwt_key_9f8a3b7c2d1e4f6a5b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e"

NEW_PASSWORD = "Sudarshan@2026"

async def reset():
    import aiosqlite
    from passlib.context import CryptContext
    
    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    hashed = pwd_ctx.hash(NEW_PASSWORD)
    
    db_path = r"d:\Projects\Sudarshan BOI\backend\sudarshan.db"
    
    if not os.path.exists(db_path):
        print(f"[ERROR] DB not found: {db_path}")
        return
    
    async with aiosqlite.connect(db_path) as db:
        # List users first
        async with db.execute("SELECT id, username, role FROM users") as cursor:
            rows = await cursor.fetchall()
            print(f"Found {len(rows)} user(s):")
            for row in rows:
                print(f"  id={row[0]} username={row[1]} role={row[2]}")
        
        # Reset admin password
        await db.execute(
            "UPDATE users SET password_hash = ? WHERE username = 'admin'",
            (hashed,)
        )
        await db.commit()
        print(f"\n[OK] Admin password reset to: {NEW_PASSWORD}")
        print("     Restart backend container for changes to take effect (or test now).")

asyncio.run(reset())
