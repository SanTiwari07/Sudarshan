import asyncio
import os
import sys
from pathlib import Path

# Setup paths relatively
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "backend"))
sys.path.insert(0, str(ROOT_DIR / "shared"))

os.environ["JWT_SECRET_KEY"] = "test_secret_key"

async def reset_admin():
    from app.db.database import get_db_connection
    from app.auth.auth import hash_password
    
    db_path = ROOT_DIR / "sudarshan.db"
    if not db_path.exists():
        db_path = ROOT_DIR / "backend" / "sudarshan.db"
    
    if not db_path.exists():
        print(f"Database not found at {db_path}")
        return
        
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    
    try:
        async with get_db_connection() as db:
            hashed_pwd = hash_password("admin123")
            await db.execute(
                "UPDATE users SET hashed_password = :hp WHERE username = :un",
                {"hp": hashed_pwd, "un": "admin"}
            )
            await db.commit()
            print("Password for 'admin' reset to 'admin123'")
    except Exception as e:
        print(f"Error resetting password: {e}")

if __name__ == "__main__":
    asyncio.run(reset_admin())
