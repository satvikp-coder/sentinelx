"""scripts/escalations.py: list/ack/resolve against the real escalations table shape (id,
finding_id, body - status lives inside body, not as its own column; a real bug where the
script queried a non-existent `status` column was only caught by running the CLI for real)."""

from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def escalations_module():
    spec = importlib.util.spec_from_file_location(
        "escalations_cli_under_test", ROOT / "scripts" / "escalations.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def conn(tmp_path):
    from sentinelx.evidence.db import connect, migrate

    c = connect(tmp_path / "db.sqlite")
    migrate(c)
    return c


def _seed_ticket(conn) -> str:
    from sentinelx.common_schemas import EscalationStatus, EscalationTicket
    from sentinelx.evidence.records import RecordStore

    ticket = EscalationTicket(
        id="esc_test1", finding_id="cand_x_0001", evidence_event_ids=["n/a"],
        explanation="needs a human", options=["a", "b"], status=EscalationStatus.OPEN,
        created_at=datetime.now(UTC))
    RecordStore(conn).insert(ticket)
    return ticket.id


def test_list_ack_resolve_round_trip(conn, escalations_module, capsys) -> None:
    ticket_id = _seed_ticket(conn)

    escalations_module._list(conn)
    assert "OPEN" in capsys.readouterr().out

    escalations_module._ack(conn, ticket_id)
    body = escalations_module._load(conn, ticket_id)
    assert body["status"] == "ACKNOWLEDGED"

    escalations_module._resolve(conn, ticket_id, "alice", "approve", "looks fine")
    body = escalations_module._load(conn, ticket_id)
    assert body["status"] == "RESOLVED"
    approvals = conn.execute("SELECT body FROM approvals").fetchall()
    assert len(approvals) == 1
    import json

    assert json.loads(approvals[0]["body"])["decision"] == "approve"

    escalations_module._list(conn)
    assert "RESOLVED" in capsys.readouterr().out


def test_load_raises_a_clear_error_for_an_unknown_ticket(conn, escalations_module) -> None:
    with pytest.raises(ValueError, match="no such escalation ticket"):
        escalations_module._load(conn, "esc_does_not_exist")
