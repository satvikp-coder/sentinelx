import sqlite3
from pathlib import Path

import pytest

from sentinelx.evidence.db import applied_versions, connect, migrate

EXPECTED_TABLES = {
    "scenarios", "sessions", "actions", "events", "incidents", "branches", "verifications",
    "usage", "audit", "targets", "scan_findings", "patches", "shield_rules", "escalations",
    "approvals", "schema_migrations", "budgets",
}


def tables(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r[0] for r in rows}


def test_fresh_database_migrates(tmp_path: Path) -> None:
    conn = connect(tmp_path / "sx.db")
    assert migrate(conn) == [1, 2, 3]
    assert EXPECTED_TABLES <= tables(conn)
    assert applied_versions(conn) == [1, 2, 3]


def test_wal_and_foreign_keys_on(tmp_path: Path) -> None:
    conn = connect(tmp_path / "sx.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_migrate_twice_is_noop(tmp_path: Path) -> None:
    conn = connect(tmp_path / "sx.db")
    migrate(conn)
    before = conn.execute("SELECT * FROM schema_migrations").fetchall()
    assert migrate(conn) == []
    assert conn.execute("SELECT * FROM schema_migrations").fetchall() == before


def test_foreign_keys_enforced(tmp_path: Path) -> None:
    conn = connect(tmp_path / "sx.db")
    migrate(conn)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO events (id, session_id, seq, kind, timestamp_utc, state, source,"
            " payload, previous_hash, event_hash, schema_version)"
            " VALUES ('e','nope',1,'k','t','OBSERVED','s','{}','a','b','1.0')"
        )


def test_events_unique_session_seq(tmp_path: Path) -> None:
    conn = connect(tmp_path / "sx.db")
    migrate(conn)
    conn.execute(
        "INSERT INTO sessions (id, kind, state, created_at, policy_version, schema_version)"
        " VALUES ('s','SCAN','CREATED','t','p','1.0')"
    )
    ins = (
        "INSERT INTO events (id, session_id, seq, kind, timestamp_utc, state, source,"
        " payload, previous_hash, event_hash, schema_version)"
        " VALUES (?,'s',1,'k','t','OBSERVED','s','{}','a','b','1.0')"
    )
    conn.execute(ins, ("e1",))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(ins, ("e2",))
