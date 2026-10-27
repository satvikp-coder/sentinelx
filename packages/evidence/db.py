"""SQLite connection (WAL, foreign keys ON) and versioned migrations."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a database. Autocommit mode; callers open explicit transactions with BEGIN."""
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _migration_files() -> list[tuple[int, str, Path]]:
    found = []
    for p in sorted(MIGRATIONS_DIR.glob("*.sql")):
        m = _NAME.match(p.name)
        if not m:
            raise ValueError(f"bad migration file name: {p.name}")
        found.append((int(m.group(1)), p.name, p))
    versions = [v for v, _, _ in found]
    if versions != list(range(1, len(versions) + 1)):
        raise ValueError(f"migration numbers must be contiguous from 0001: {versions}")
    return found


def applied_versions(conn: sqlite3.Connection) -> list[int]:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    return [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]


def migrate(conn: sqlite3.Connection) -> list[int]:
    """Apply pending migrations in order. Returns the versions applied (empty = no-op)."""
    done = set(applied_versions(conn))
    applied: list[int] = []
    for version, name, path in _migration_files():
        if version in done:
            continue
        sql = path.read_text(encoding="utf-8")
        stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        # executescript runs as one script; BEGIN/COMMIT make the migration + its record atomic.
        script = (
            "BEGIN;\n" + sql + "\n"
            f"INSERT INTO schema_migrations (version, name, applied_at) "
            f"VALUES ({version}, '{name}', '{stamp}');\nCOMMIT;"
        )
        try:
            conn.executescript(script)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        applied.append(version)
    return applied


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[None]:
    """BEGIN IMMEDIATE ... COMMIT; joins the caller's transaction if one is already open."""
    if conn.in_transaction:
        yield
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")
