import os
import re
import logging
from typing import Any, AsyncIterator, List, Optional, Tuple, Dict
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

class CursorWrapper:
    def __init__(self, fetchone_cb, fetchall_cb, rowcount: int, lastrowid: Optional[int]):
        self._fetchone = fetchone_cb
        self._fetchall = fetchall_cb
        self.rowcount = rowcount
        self.lastrowid = lastrowid

    async def fetchone(self) -> Optional[Dict[str, Any]]:
        return await self._fetchone()

    async def fetchall(self) -> List[Dict[str, Any]]:
        return await self._fetchall()

class AwaitableCursor:
    def __init__(self, coro):
        self._coro = coro

    def __await__(self):
        return self._coro.__await__()

    async def __aenter__(self):
        return await self._coro

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

class ConnectionWrapper:
    def __init__(self):
        self._row_factory = None

    @property
    def row_factory(self):
        return self._row_factory

    @row_factory.setter
    def row_factory(self, val):
        self._row_factory = val

    def execute(self, sql: str, params: tuple = ()) -> AwaitableCursor:
        return AwaitableCursor(self._execute_internal(sql, params))

    def executemany(self, sql: str, params_list: List[tuple]) -> AwaitableCursor:
        return AwaitableCursor(self._executemany_internal(sql, params_list))

    async def _execute_internal(self, sql: str, params: tuple) -> CursorWrapper:
        raise NotImplementedError

    async def _executemany_internal(self, sql: str, params_list: List[tuple]) -> CursorWrapper:
        raise NotImplementedError

    async def commit(self):
        pass

    async def rollback(self):
        pass

def convert_qmark_to_dollar(sql: str) -> str:
    in_single_quote = False
    in_double_quote = False
    param_idx = 1
    out = []
    
    i = 0
    while i < len(sql):
        c = sql[i]
        if c == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            out.append(c)
        elif c == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            out.append(c)
        elif c == '?' and not in_single_quote and not in_double_quote:
            out.append(f"${param_idx}")
            param_idx += 1
        else:
            out.append(c)
        i += 1
            
    return "".join(out)

class PostgresRow(dict):
    def __init__(self, record):
        super().__init__(record)
        self._keys = list(record.keys())
        self._values = list(record.values())

    def __getitem__(self, item):
        if isinstance(item, int):
            return self._values[item]
        return super().__getitem__(item)

class AsyncpgConnectionWrapper(ConnectionWrapper):
    def __init__(self, conn, tr):
        super().__init__()
        self.conn = conn
        self._tr = tr

    async def _ensure_tr(self):
        if not self._tr:
            self._tr = self.conn.transaction()
            await self._tr.start()

    async def commit(self):
        if self._tr:
            await self._tr.commit()
            self._tr = None

    async def rollback(self):
        if self._tr:
            await self._tr.rollback()
            self._tr = None

    async def _execute_internal(self, sql: str, params: tuple) -> CursorWrapper:
        await self._ensure_tr()
        pg_sql = convert_qmark_to_dollar(sql)
        
        # Dialect conversion for PostgreSQL
        if "AUTOINCREMENT" in pg_sql.upper():
            import re
            pg_sql = re.sub(r'INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT', 'SERIAL PRIMARY KEY', pg_sql, flags=re.IGNORECASE)
            
        is_select = pg_sql.strip().upper().startswith(("SELECT", "WITH", "PRAGMA"))
        
        if pg_sql.strip().upper().startswith("PRAGMA"):
            async def _empty_fetchone():
                return None
            async def _empty_fetchall():
                return []
            return CursorWrapper(
                fetchone_cb=_empty_fetchone,
                fetchall_cb=_empty_fetchall,
                rowcount=0,
                lastrowid=None
            )

        if is_select:
            stmt = await self.conn.prepare(pg_sql)
            records = await stmt.fetch(*params)
            
            async def _fetchone():
                if records:
                    return PostgresRow(records[0])
                return None
                
            async def _fetchall():
                return [PostgresRow(r) for r in records]
                
            return CursorWrapper(
                fetchone_cb=_fetchone,
                fetchall_cb=_fetchall,
                rowcount=len(records),
                lastrowid=None
            )
        else:
            rowcount = 0
            # For Postgres, lastrowid relies on RETURNING id.
            lastrowid = None
            if "RETURNING" in pg_sql.upper():
                stmt = await self.conn.prepare(pg_sql)
                records = await stmt.fetch(*params)
                if records and "id" in records[0]:
                    lastrowid = records[0]["id"]
                rowcount = len(records)
                
                async def _fetchone():
                    return PostgresRow(records[0]) if records else None
                async def _fetchall():
                    return [PostgresRow(r) for r in records]
                    
                return CursorWrapper(
                    fetchone_cb=_fetchone,
                    fetchall_cb=_fetchall,
                    rowcount=rowcount,
                    lastrowid=lastrowid
                )
            else:
                status = await self.conn.execute(pg_sql, *params)
                parts = status.split()
                if len(parts) > 1 and parts[-1].isdigit():
                    rowcount = int(parts[-1])

                async def _empty_fetchone():
                    return None
                async def _empty_fetchall():
                    return []
                    
                return CursorWrapper(
                    fetchone_cb=_empty_fetchone,
                    fetchall_cb=_empty_fetchall,
                    rowcount=rowcount,
                    lastrowid=lastrowid
                )

    async def _executemany_internal(self, sql: str, params_list: List[tuple]) -> CursorWrapper:
        await self._ensure_tr()
        pg_sql = convert_qmark_to_dollar(sql)
        await self.conn.executemany(pg_sql, params_list)
        
        async def _empty_fetchone():
            return None
        async def _empty_fetchall():
            return []
            
        return CursorWrapper(
            fetchone_cb=_empty_fetchone,
            fetchall_cb=_empty_fetchall,
            rowcount=len(params_list),
            lastrowid=None
        )

class AiosqliteConnectionWrapper(ConnectionWrapper):
    def __init__(self, conn):
        super().__init__()
        self.conn = conn

    async def _execute_internal(self, sql: str, params: tuple) -> CursorWrapper:
        self.conn.row_factory = __import__("aiosqlite").Row
        cur = await self.conn.execute(sql, params)
        
        async def _fetchone():
            return await cur.fetchone()
            
        async def _fetchall():
            return await cur.fetchall()
            
        return CursorWrapper(
            fetchone_cb=_fetchone,
            fetchall_cb=_fetchall,
            rowcount=cur.rowcount,
            lastrowid=cur.lastrowid
        )

    async def _executemany_internal(self, sql: str, params_list: List[tuple]) -> CursorWrapper:
        cur = await self.conn.executemany(sql, params_list)
        return CursorWrapper(
            fetchone_cb=lambda: None,
            fetchall_cb=lambda: [],
            rowcount=cur.rowcount,
            lastrowid=cur.lastrowid
        )

    async def commit(self):
        await self.conn.commit()

    async def rollback(self):
        await self.conn.rollback()


DB_POOL = None
IS_POSTGRES = False

async def init_pool():
    global DB_POOL, IS_POSTGRES
    db_url = os.getenv("DATABASE_URL")
    
    if db_url and db_url.startswith("postgresql"):
        import asyncpg
        IS_POSTGRES = True
        # remove dialect prefix for asyncpg
        if db_url.startswith("postgresql+asyncpg://"):
            db_url = db_url.replace("postgresql+asyncpg://", "postgresql://")
        
        DB_POOL = await asyncpg.create_pool(db_url, min_size=1, max_size=20)
        logger.info(f"[DB] Connected to PostgreSQL via asyncpg pool.")
    else:
        IS_POSTGRES = False
        logger.info(f"[DB] Using local SQLite fallback.")

@asynccontextmanager
async def connect():
    if IS_POSTGRES:
        async with DB_POOL.acquire() as conn:
            tr = conn.transaction()
            await tr.start()
            wrapper = AsyncpgConnectionWrapper(conn, tr)
            try:
                yield wrapper
            except Exception:
                await wrapper.rollback()
                raise
            else:
                await wrapper.commit()
    else:
        import aiosqlite
        from app.db.paths import resolve_db_path, ensure_parent
        from pathlib import Path
        
        path = str(resolve_db_path())
        ensure_parent(Path(path))
        async with aiosqlite.connect(path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA busy_timeout=5000;")
            await db.execute("PRAGMA foreign_keys=ON;")
            yield AiosqliteConnectionWrapper(db)

def is_postgres() -> bool:
    return IS_POSTGRES

import asyncio
from functools import wraps

def with_db_retry(max_retries: int = 3, base_delay: float = 0.5):
    """
    Retry a database operation if a transient connection error occurs.
    Exponential backoff is applied between retries.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            retries = 0
            while True:
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    # In asyncpg, transient errors might be subclasses of PostgresConnectionError
                    # In sqlite, transient errors are OperationalError ("database is locked")
                    error_name = type(e).__name__
                    is_transient = "Connection" in error_name or "OperationalError" in error_name or "Timeout" in error_name
                    
                    if not is_transient or retries >= max_retries:
                        raise
                        
                    delay = base_delay * (2 ** retries)
                    logger.warning(f"[DB] Transient error in {func.__name__}: {e}. Retrying in {delay}s...")
                    await asyncio.sleep(delay)
                    retries += 1
        return wrapper
    return decorator
