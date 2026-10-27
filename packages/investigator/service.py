"""Investigate one session: model if available, else the deterministic baseline; verify
independently; store the finding and its verification in the evidence store."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass

from sentinelx.common_schemas import EvidenceState, FindingState, IncidentFinding
from sentinelx.evidence.db import transaction
from sentinelx.evidence.records import RecordStore
from sentinelx.evidence.store import EvidenceStore
from sentinelx.model_clients import ModelClient, ModelResult

from .baseline import baseline_from_facts
from .facts import build_facts
from .model_investigator import UNAVAILABLE_NOTE, model_investigate
from .verify import FINDING_VERIFIER_VERSION, FindingVerification, verify_finding

FINDING_EVENT = "INCIDENT_FINDING"
VERIFIED_EVENT = "FINDING_VERIFIED"


@dataclass
class Investigation:
    finding: IncidentFinding  # final: finding_state/verifier_version set by the verifier
    verification: FindingVerification
    mode: str  # MODEL | BASELINE
    note: str  # "model unavailable: baseline used (...)" or ""
    model_result: ModelResult | None
    finding_event_id: str | None = None
    verified_event_id: str | None = None


def investigate(conn: sqlite3.Connection, session_id: str, client: ModelClient | None = None,
                *, store_result: bool = True) -> Investigation:
    """`client=None` (or an unavailable model) gives the BASELINE finding, labelled as such."""
    facts = build_facts(conn, session_id)
    baseline = baseline_from_facts(session_id, facts)
    draft, note, model_result = baseline, "", None
    if client is not None:
        attempt = model_investigate(conn, session_id, client, facts)
        model_result = attempt.result
        if attempt.finding is not None:
            draft = attempt.finding
        else:
            note = attempt.note or UNAVAILABLE_NOTE
            draft = baseline.model_copy(update={"finding": f"[{note}] {baseline.finding}"})
    verification = verify_finding(conn, session_id, draft)
    final = draft.model_copy(update={"finding_state": verification.state,
                                     "verifier_version": FINDING_VERIFIER_VERSION})
    inv = Investigation(final, verification, final.investigator_mode or "BASELINE", note,
                        model_result)
    if store_result:
        _store(conn, session_id, inv)
    return inv


def _store(conn: sqlite3.Connection, session_id: str, inv: Investigation) -> None:
    n = conn.execute("SELECT COUNT(*) FROM incidents WHERE session_id = ?",
                     (session_id,)).fetchone()[0]
    final = inv.finding.model_copy(update={"incident_id": f"{inv.finding.incident_id}_{n + 1}"})
    inv.finding = final
    store = EvidenceStore(conn)
    with transaction(conn):
        found = store.append(session_id, FINDING_EVENT, EvidenceState.INFERRED, "investigator", {
            "finding": final.model_dump(mode="json"), "note": inv.note,
            "investigator_mode": inv.mode})
        confirmed = inv.verification.state is FindingState.CONFIRMED
        verified = store.append(
            session_id, VERIFIED_EVENT,
            EvidenceState.VERIFIED if confirmed else EvidenceState.OBSERVED, "finding_verifier",
            {"incident_id": final.incident_id, "finding_state": inv.verification.state.value,
             "flagged": not confirmed, "verification": inv.verification.model_dump(mode="json")},
            parent_event_id=found.id)
        RecordStore(conn).insert(final, session_id=session_id)
    inv.finding_event_id, inv.verified_event_id = found.id, verified.id


def citation_fidelity(verifications: Iterable[FindingVerification]) -> tuple[int, int]:
    """(claims with verified support, claims evaluated) summed over findings."""
    num = den = 0
    for v in verifications:
        num += v.citation_numerator
        den += v.citation_denominator
    return num, den
