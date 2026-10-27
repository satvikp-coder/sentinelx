import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinelx.common_schemas import (
    AuditRecord,
    ScanFinding,
    ScenarioSpec,
    SessionRecord,
    TargetAuthorization,
    UsageRecord,
)
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.records import RecordStore
from tests.unit.test_schemas import valid_samples

NOW = datetime(2026, 10, 27, tzinfo=UTC)


@pytest.fixture()
def store(tmp_path: Path) -> RecordStore:
    conn = connect(tmp_path / "r.db")
    migrate(conn)
    return RecordStore(conn)


def test_insert_and_get_roundtrip(store: RecordStore) -> None:
    sc = ScenarioSpec.model_validate(valid_samples()["ScenarioSpec"])
    store.insert(sc)
    assert store.get(ScenarioSpec, "sc1") == sc
    assert store.get(ScenarioSpec, "missing") is None


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_invalid_model_never_written(store: RecordStore) -> None:
    bad = ScenarioSpec.model_construct(id="x", seed="not-an-int")  # bypasses validation
    with pytest.raises((ValidationError, TypeError)):
        store.insert(bad)
    n = store.conn.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
    assert n == 0


def test_foreign_key_enforced_for_scan_finding(store: RecordStore) -> None:
    f = ScanFinding.model_validate(valid_samples()["ScanFinding"])
    with pytest.raises(sqlite3.IntegrityError):
        store.insert(f)
    store.insert(TargetAuthorization.model_validate(valid_samples()["TargetAuthorization"]))
    store.insert(f)
    assert store.get(ScanFinding, "f1") == f


def test_secrets_redacted_before_write(store: RecordStore) -> None:
    store.insert(TargetAuthorization.model_validate(valid_samples()["TargetAuthorization"]))
    data = dict(valid_samples()["ScanFinding"])
    data["redacted_response_excerpt"] = "Set-Cookie: sid=fakefakefake; password=hunter2fake"
    store.insert(ScanFinding.model_validate(data))
    raw = store.conn.execute("SELECT body FROM scan_findings").fetchone()[0]
    assert "fakefakefake" not in raw and "hunter2fake" not in raw


def test_session_usage_audit_tables(store: RecordStore) -> None:
    s = SessionRecord.model_validate(valid_samples()["SessionRecord"])
    store.insert(s)
    store.insert(UsageRecord.model_validate(valid_samples()["UsageRecord"] | {"session_id": "s1"}))
    store.insert(AuditRecord.model_validate(valid_samples()["AuditRecord"] | {"session_id": "s1"}))
    assert store.conn.execute("SELECT COUNT(*) FROM usage").fetchone()[0] == 1
    assert store.conn.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == 1
    assert store.get(SessionRecord, "s1") == s
