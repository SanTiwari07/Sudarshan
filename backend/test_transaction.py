import pytest
import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.db.pool import connect
from app.db.database import get_case

@pytest.mark.asyncio
async def test_rollback():
    os.environ["DATABASE_URL"] = "postgresql://sudarshan:sudarshan@localhost:5432/sudarshan"
    
    sha256 = "fail_txn_test"
    try:
        async with connect() as db:
            await db.execute(
                "INSERT INTO cases (sha256, package_name, created_at) VALUES (?, ?, ?)",
                (sha256, "com.fail", "2026-01-01T00:00:00Z")
            )
            # simulate failure before commit
            raise ValueError("Intentional crash")
            await db.commit()
    except ValueError:
        pass
        
    case = await get_case(sha256)
    assert case is None, "Transaction was NOT rolled back!"
    print("Transaction Safety Test PASSED")

if __name__ == "__main__":
    asyncio.run(test_rollback())
