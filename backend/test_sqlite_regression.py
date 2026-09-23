import asyncio
import os
import sys

# Ensure backend module is resolvable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.pool import init_pool
from app.db.database import init_db, list_users, create_user

async def main():
    # Force sqlite connection
    os.environ["DATABASE_URL"] = ""
    db_path = os.path.abspath("test_regression.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    os.environ["SUDARSHAN_DB_PATH"] = db_path
    
    # We must patch the DB_PATH dynamically because it's resolved at import time
    import app.db.database as db
    db.DB_PATH = db_path

    print("Running init_db() with SQLite...")
    await init_db()
    print("Tables and migrations applied.")
    
    users = await list_users()
    print(f"Users found (should be empty): {len(users)}")
    assert len(users) == 0
    
    print("Creating a user...")
    user_id = await create_user("testuser", "hashed", "analyst")
    print(f"User created with ID: {user_id}")
    assert user_id is not None
    
    users = await list_users()
    print(f"Users found (should be 1): {len(users)}")
    assert len(users) == 1
    
    # Test case creation
    from app.db.database import save_case, get_case, upsert_analysis_job, load_analysis_job
    print("Saving case...")
    await save_case("1234567890abcdef", {"package_name": "com.test.app", "final_risk_score": 50.0}, user_id)
    
    case = await get_case("1234567890abcdef")
    print(f"Retrieved case: {case.get('package_name')}")
    assert case["package_name"] == "com.test.app"
    
    print("Upserting job...")
    job = {
        "job_id": "job-1",
        "status": "QUEUED",
        "sha256": "1234567890abcdef",
        "analyst_id": user_id,
        "queued_at": "2026-09-23T00:00:00Z"
    }
    await upsert_analysis_job(job)
    
    loaded_job = await load_analysis_job("job-1")
    print(f"Loaded job: {loaded_job.get('job_id')} with status {loaded_job.get('status')}")
    assert loaded_job["job_id"] == "job-1"
    
    print("SQLite regression test PASSED")
    
if __name__ == "__main__":
    asyncio.run(main())
