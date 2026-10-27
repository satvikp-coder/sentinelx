"""Run the verifier and persist its result (evidence event VERIFIED + verifications table)."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from typing import Any

from sentinelx.common_schemas import EvidenceState, ScenarioSpec, VerifierResult
from sentinelx.evidence.db import transaction
from sentinelx.evidence.records import RecordStore
from sentinelx.evidence.store import EvidenceStore

from .verify import RunRecord, verify_run

VERIFIER_EVENT = "VERIFIER_RESULT"


def verify_and_record(
    conn: sqlite3.Connection,
    scenario: ScenarioSpec,
    session_id: str,
    ledger: Sequence[dict[str, Any]],
) -> VerifierResult:
    store = EvidenceStore(conn)
    result = verify_run(scenario, RunRecord(session_id, store.list_session(session_id)), ledger)
    with transaction(conn):
        store.append(
            session_id, VERIFIER_EVENT, EvidenceState.VERIFIED, "independent_verifier",
            {"result": result.model_dump(mode="json")},
        )
        RecordStore(conn).insert(result)
    return result
