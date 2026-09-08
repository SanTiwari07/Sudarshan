#!/usr/bin/env python3
"""
Sudarshan database operator tool.
=================================

    python scripts/db_admin.py locate           where is the database, and why
    python scripts/db_admin.py inspect [PATH]   tables, row counts, schema version
    python scripts/db_admin.py adopt  SRC        copy a legacy database into place
    python scripts/db_admin.py backup [DEST]     safe hot backup
    python scripts/db_admin.py verify  PATH      integrity + foreign-key check
    python scripts/db_admin.py restore SRC       restore a backup over the live DB
    python scripts/db_admin.py prune  [--apply]  apply retention policy

Backups use SQLite's own backup API
-----------------------------------
`cp sudarshan.db backup.db` on a WAL database is not a backup. The file on disk
is only part of the state: recent transactions live in `-wal`, and copying the
three files with three separate reads can capture them at three different
points. The result opens without complaint and is silently short of data, or
corrupt.

`sqlite3.Connection.backup()` takes a consistent snapshot of a live database
while writers continue, and produces a single self-contained file. That is what
`backup` and `adopt` use.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "backend"))

# Retention policy. Nothing here deletes an audit event or a case: those are the
# record of what happened and what was found. Only operational state expires.
RETENTION = {
    "sessions":       ("expires_at",   7,   "expired sessions (login history is in login_attempts)"),
    "login_attempts": ("attempted_at", 90,  "old authentication attempts"),
    "ioc_cache":      ("expires_at",   7,   "expired reputation cache entries"),
    "analysis_jobs":  ("completed_at", 30,  "completed job records (the case row is permanent)"),
    "runtime_events": ("ts",           30,  "runtime event index (evidence files are untouched)"),
}

NEVER_PRUNED = {
    "audit_events": "the audit trail - it is evidence, not cache",
    "cases":        "case records",
    "case_notes":   "analyst notes",
    "case_iocs":    "indicator relationships",
    "analysis_runs": "analysis history / trending",
    "chat_messages": "investigation conversations",
    "export_events": "the export ledger - part of the audit story",
    "users":        "accounts",
}


def _resolve() -> Path:
    from app.db.paths import resolve_db_path
    return resolve_db_path()


def _reason() -> str:
    from app.db.paths import resolution_reason
    return resolution_reason()


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=15.0)
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def _table_names(conn: sqlite3.Connection) -> list:
    return [
        r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]


# ─── Commands ─────────────────────────────────────────────────────────────────

def cmd_locate(_args) -> int:
    from app.db.paths import ENV_DB_PATH, default_db_path, legacy_db_path

    path = _resolve()
    print(f"resolved path : {path}")
    print(f"reason        : {_reason()}")
    print(f"exists        : {path.exists()}"
          + (f"  ({path.stat().st_size:,} bytes)" if path.exists() else ""))
    print(f"{ENV_DB_PATH:<14}: {os.getenv(ENV_DB_PATH) or '(unset)'}")
    print(f"cwd           : {Path.cwd()}")
    print()
    print("other candidates on this machine:")
    seen = {path.resolve()}
    for cand in (legacy_db_path(), default_db_path(),
                 _REPO_ROOT / "sudarshan.db",
                 _REPO_ROOT / "backend" / "sudarshan.db",
                 _REPO_ROOT / "analysis-engine" / "sudarshan.db"):
        rp = cand.resolve()
        if rp in seen or not cand.exists():
            continue
        seen.add(rp)
        try:
            conn = _connect(cand)
            cases = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
            users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            conn.close()
            detail = f"cases={cases} users={users}"
        except sqlite3.Error as exc:
            detail = f"unreadable: {exc}"
        print(f"  {cand}  ({cand.stat().st_size:,} bytes)  {detail}")
    return 0


def cmd_inspect(args) -> int:
    path = Path(args.path) if args.path else _resolve()
    if not path.exists():
        print(f"no database at {path}", file=sys.stderr)
        return 1

    conn = _connect(path)
    print(f"{path}  ({path.stat().st_size:,} bytes)")
    print(f"journal_mode : {conn.execute('PRAGMA journal_mode').fetchone()[0]}")

    try:
        rows = conn.execute(
            "SELECT version, applied_at FROM schema_migrations ORDER BY version"
        ).fetchall()
        print(f"migrations   : {len(rows)} applied")
        for v, at in rows:
            print(f"               {v}  {at}")
    except sqlite3.Error:
        print("migrations   : no schema_migrations table (pre-migration database)")

    print("\ntables:")
    for name in _table_names(conn):
        count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        note = ""
        if name == "analysis_runs":
            try:
                ph = conn.execute(
                    "SELECT COUNT(*) FROM analysis_runs WHERE is_placeholder = 1"
                ).fetchone()[0]
                if ph:
                    note = f"   ({ph} placeholder row(s), excluded from comparisons)"
            except sqlite3.Error:
                pass
        print(f"  {name:<24} {count:>8,}{note}")
    conn.close()
    return 0


def cmd_verify(args) -> int:
    path = Path(args.path) if args.path else _resolve()
    if not path.exists():
        print(f"no database at {path}", file=sys.stderr)
        return 1

    conn = _connect(path)
    ok = True

    integrity = conn.execute("PRAGMA integrity_check").fetchall()
    if integrity == [("ok",)]:
        print("integrity_check : ok")
    else:
        ok = False
        print("integrity_check : FAILED")
        for row in integrity[:20]:
            print("   ", row[0])

    conn.execute("PRAGMA foreign_keys=ON")
    violations = conn.execute("PRAGMA foreign_key_check").fetchall()
    if not violations:
        print("foreign_key_check: ok")
    else:
        ok = False
        print(f"foreign_key_check: {len(violations)} violation(s)")
        for row in violations[:20]:
            print(f"    table={row[0]} rowid={row[1]} refers to {row[2]}")

    conn.close()
    print("\nRESULT:", "OK" if ok else "PROBLEMS FOUND")
    return 0 if ok else 2


def _safe_copy(src: Path, dest: Path) -> None:
    """Consistent snapshot of a live WAL database - see the module docstring."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    source = _connect(src)
    target = sqlite3.connect(str(dest))
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def cmd_backup(args) -> int:
    path = _resolve()
    if not path.exists():
        print(f"no database at {path}", file=sys.stderr)
        return 1

    if args.dest:
        dest = Path(args.dest)
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        dest = path.parent / "backups" / f"sudarshan-{stamp}.db"

    _safe_copy(path, dest)
    print(f"backed up {path} -> {dest}  ({dest.stat().st_size:,} bytes)")

    conn = _connect(dest)
    result = conn.execute("PRAGMA integrity_check").fetchone()[0]
    conn.close()
    print(f"integrity_check on the backup: {result}")
    return 0 if result == "ok" else 2


def cmd_adopt(args) -> int:
    """
    Copy an existing database into the resolved location.

    For moving off the old CWD-relative layout onto an explicit
    SUDARSHAN_DB_PATH (a mounted volume) without losing the existing cases.
    Refuses to overwrite unless --force, and always keeps a copy of whatever it
    replaces.
    """
    src = Path(args.src)
    dest = _resolve()

    if not src.exists():
        print(f"source does not exist: {src}", file=sys.stderr)
        return 1
    if src.resolve() == dest.resolve():
        print(f"source and destination are the same file ({dest}); nothing to do")
        return 0

    if dest.exists():
        if not args.force:
            print(
                f"destination already exists: {dest}\n"
                f"Refusing to overwrite. Inspect both first:\n"
                f"    python scripts/db_admin.py inspect {src}\n"
                f"    python scripts/db_admin.py inspect {dest}\n"
                f"then re-run with --force if the source really is authoritative.",
                file=sys.stderr,
            )
            return 1
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        kept = dest.parent / f"{dest.stem}.replaced-{stamp}{dest.suffix}"
        _safe_copy(dest, kept)
        print(f"kept the existing destination at {kept}")

    _safe_copy(src, dest)
    print(f"adopted {src} -> {dest}  ({dest.stat().st_size:,} bytes)")
    print("The source file was NOT deleted. Remove it once you have verified the move.")
    return 0


def cmd_restore(args) -> int:
    src = Path(args.src)
    dest = _resolve()
    if not src.exists():
        print(f"backup does not exist: {src}", file=sys.stderr)
        return 1

    conn = _connect(src)
    check = conn.execute("PRAGMA integrity_check").fetchone()[0]
    conn.close()
    if check != "ok":
        print(f"refusing to restore: the backup fails integrity_check ({check})",
              file=sys.stderr)
        return 2

    if dest.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        kept = dest.parent / f"{dest.stem}.pre-restore-{stamp}{dest.suffix}"
        _safe_copy(dest, kept)
        print(f"current database preserved at {kept}")

    # Stale -wal/-shm alongside a replaced file would be applied on top of it.
    for suffix in ("-wal", "-shm"):
        stale = Path(str(dest) + suffix)
        if stale.exists():
            stale.unlink()

    shutil.copy2(src, dest)
    print(f"restored {src} -> {dest}")
    print("Restart the backend so it reopens the file.")
    return 0


def cmd_prune(args) -> int:
    path = _resolve()
    if not path.exists():
        print(f"no database at {path}", file=sys.stderr)
        return 1

    conn = _connect(path)
    existing = set(_table_names(conn))
    total = 0

    print(f"{'APPLYING' if args.apply else 'DRY RUN'} retention on {path}\n")
    for table, (column, days, description) in RETENTION.items():
        if table not in existing:
            continue
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        sql_where = f'WHERE "{column}" IS NOT NULL AND "{column}" < ?'
        n = conn.execute(f'SELECT COUNT(*) FROM "{table}" {sql_where}', (cutoff,)).fetchone()[0]
        total += n
        print(f"  {table:<18} {n:>8,}  older than {days:>3}d   {description}")
        if args.apply and n:
            conn.execute(f'DELETE FROM "{table}" {sql_where}', (cutoff,))

    if args.apply:
        conn.commit()
        conn.execute("VACUUM")
        print(f"\ndeleted {total:,} row(s) and vacuumed")
    else:
        print(f"\nwould delete {total:,} row(s). Re-run with --apply to do it.")

    print("\nnever pruned:")
    for table, why in NEVER_PRUNED.items():
        if table in existing:
            count = conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            print(f"  {table:<18} {count:>8,}  {why}")
    conn.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("locate", help="show the resolved database path and why")

    p = sub.add_parser("inspect", help="tables, row counts, schema version")
    p.add_argument("path", nargs="?")

    p = sub.add_parser("verify", help="integrity and foreign-key check")
    p.add_argument("path", nargs="?")

    p = sub.add_parser("backup", help="safe hot backup via the SQLite backup API")
    p.add_argument("dest", nargs="?")

    p = sub.add_parser("adopt", help="copy a legacy database into the resolved location")
    p.add_argument("src")
    p.add_argument("--force", action="store_true",
                   help="overwrite the destination (a copy is kept)")

    p = sub.add_parser("restore", help="restore a backup over the live database")
    p.add_argument("src")

    p = sub.add_parser("prune", help="apply the retention policy")
    p.add_argument("--apply", action="store_true", help="actually delete (default: dry run)")

    args = parser.parse_args()
    return {
        "locate": cmd_locate, "inspect": cmd_inspect, "verify": cmd_verify,
        "backup": cmd_backup, "adopt": cmd_adopt, "restore": cmd_restore,
        "prune": cmd_prune,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
