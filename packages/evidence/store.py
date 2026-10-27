"""Append-only, hash-chained evidence store.

This provides tamper-EVIDENCE (changes to stored rows are detectable), not a forensic chain of
custody: anyone with write access to the database file AND the ability to recompute every later
hash can forge a consistent chain, and removing the *tail* is only detectable against an
externally held ``expected_last_hash``. The algorithm is specified in docs/ARCHITECTURE.md.

Public API is deliberately only: append(), get(), list_session(), verify_chain(), resolve_refs().
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from sentinelx.common_schemas import EvidenceEvent, EvidenceState, format_utc
from sentinelx.policy.redaction import redact

from .db import transaction

GENESIS_HASH = "0" * 64


class ChainStatus(StrEnum):
    OK = "OK"
    MODIFIED = "MODIFIED"
    MISSING = "MISSING"
    REORDERED = "REORDERED"


@dataclass(frozen=True)
class ChainVerification:
    status: ChainStatus
    events_checked: int
    first_broken_event_id: str | None = None
    first_broken_seq: int | None = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status is ChainStatus.OK


def canonical_json(event: EvidenceEvent) -> bytes:
    """Canonical JSON of every field except event_hash: sorted keys, no extra whitespace, UTF-8."""
    doc = event.model_dump(mode="json", exclude={"event_hash"})
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def compute_event_hash(event: EvidenceEvent) -> str:
    """event_hash = hex(SHA-256(canonical_json(event) || previous_hash as ASCII))."""
    return hashlib.sha256(canonical_json(event) + event.previous_hash.encode("ascii")).hexdigest()


def _row_to_event(row: sqlite3.Row) -> EvidenceEvent:
    return EvidenceEvent.model_validate(
        {
            "schema_version": row["schema_version"],
            "id": row["id"],
            "session_id": row["session_id"],
            "seq": row["seq"],
            "kind": row["kind"],
            "timestamp_utc": row["timestamp_utc"],
            "parent_event_id": row["parent_event_id"],
            "state": row["state"],
            "source": row["source"],
            "payload": json.loads(row["payload"]),
            "previous_hash": row["previous_hash"],
            "event_hash": row["event_hash"],
        }
    )


class EvidenceStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # ------------------------------------------------------------------ write
    def append(
        self,
        session_id: str,
        kind: str,
        state: EvidenceState,
        source: str,
        payload: dict[str, Any],
        parent_event_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> EvidenceEvent:
        """Redact the payload, chain it to the session's previous event, and store it."""
        clean_payload = redact(payload).value
        with transaction(self._conn):
            last = self._conn.execute(
                "SELECT seq, event_hash FROM events WHERE session_id = ? ORDER BY seq DESC LIMIT 1",
                (session_id,),
            ).fetchone()
            seq = 1 if last is None else last["seq"] + 1
            previous = GENESIS_HASH if last is None else last["event_hash"]
            draft = EvidenceEvent(
                id=f"evt_{uuid.uuid4().hex}",
                session_id=session_id,
                seq=seq,
                kind=kind,
                timestamp_utc=timestamp or datetime.now(UTC),
                parent_event_id=parent_event_id,
                state=state,
                source=source,
                payload=clean_payload,
                previous_hash=previous,
                event_hash=GENESIS_HASH,  # placeholder, replaced below
            )
            event = draft.model_copy(update={"event_hash": compute_event_hash(draft)})
            self._conn.execute(
                "INSERT INTO events (id, session_id, seq, kind, timestamp_utc, parent_event_id,"
                " state, source, payload, previous_hash, event_hash, schema_version)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event.id, event.session_id, event.seq, event.kind,
                    format_utc(event.timestamp_utc), event.parent_event_id, event.state.value,
                    event.source, json.dumps(event.payload, sort_keys=True), event.previous_hash,
                    event.event_hash, event.schema_version,
                ),
            )
        return event

    # ------------------------------------------------------------------ read
    def get(self, event_id: str) -> EvidenceEvent | None:
        row = self._conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        return None if row is None else _row_to_event(row)

    def list_session(self, session_id: str) -> list[EvidenceEvent]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY seq", (session_id,)
        ).fetchall()
        return [_row_to_event(r) for r in rows]

    def resolve_refs(self, event_ids: Iterable[str], session_id: str) -> list[str]:
        """Return the cited ids that do NOT exist in ``session_id`` (order preserved)."""
        ids = list(event_ids)
        if not ids:
            return []
        marks = ",".join("?" for _ in ids)
        found = {
            r[0]
            for r in self._conn.execute(
                f"SELECT id FROM events WHERE session_id = ? AND id IN ({marks})",  # noqa: S608
                [session_id, *ids],
            )
        }
        return [i for i in ids if i not in found]

    # ------------------------------------------------------------------ verify
    def verify_chain(
        self, session_id: str, expected_last_hash: str | None = None
    ) -> ChainVerification:
        """Return OK, or the FIRST broken event and whether it was modified / missing / reordered.

        MISSING reports the first surviving event after the gap. A rewritten-and-rehashed event
        is reported at the rewritten event (found via the next event's broken link).
        """
        rows = self._conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY seq", (session_id,)
        ).fetchall()
        n = len(rows)
        prev_hash, prev_id, expected_seq = GENESIS_HASH, None, 1
        for row in rows:
            rid, rseq = row["id"], row["seq"]

            def broken(status: ChainStatus, detail: str, _id=rid, _seq=rseq) -> ChainVerification:
                return ChainVerification(status, n, _id, _seq, detail)

            if rseq != expected_seq:
                return broken(
                    ChainStatus.MISSING,
                    f"expected seq {expected_seq}, found {rseq}: event(s) deleted before this one",
                )
            try:
                event = _row_to_event(row)
            except (ValidationError, ValueError) as exc:
                return broken(ChainStatus.MODIFIED, f"stored row invalid: {type(exc).__name__}")
            if compute_event_hash(event) != row["event_hash"]:
                for alt in range(1, n + 1):
                    if alt != rseq and compute_event_hash(
                        event.model_copy(update={"seq": alt})
                    ) == row["event_hash"]:
                        return broken(
                            ChainStatus.REORDERED,
                            f"content was sealed at seq {alt} but sits at seq {rseq}",
                        )
                return broken(ChainStatus.MODIFIED, "stored fields do not match event_hash")
            if row["previous_hash"] != prev_hash:
                if prev_id is None:
                    return broken(ChainStatus.MODIFIED, "first event does not chain to genesis")
                known = {r["event_hash"] for r in rows}
                if row["previous_hash"] in known:
                    return broken(ChainStatus.REORDERED, "previous_hash is another event's hash")
                return ChainVerification(
                    ChainStatus.MODIFIED, n, prev_id, rseq - 1,
                    "event was altered and re-hashed: successor's previous_hash does not match",
                )
            prev_hash, prev_id, expected_seq = row["event_hash"], rid, expected_seq + 1
        if expected_last_hash is not None and prev_hash != expected_last_hash:
            return ChainVerification(
                ChainStatus.MISSING, n, None, None,
                "chain head differs from the externally anchored hash (tail removed or replaced)",
            )
        return ChainVerification(ChainStatus.OK, n)
