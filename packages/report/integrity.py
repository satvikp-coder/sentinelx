"""Build-time evidence integrity check for the static report.

For every evidence session id referenced by the loaded reports, run the existing
``verify_chain`` against a given evidence DB and record OK or the first broken event id.
This is a BUILD-TIME check of stored evidence, not a live one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.evidence.db import connect
from sentinelx.evidence.store import EvidenceStore

from .loader import _read_json

CANDIDATE_DBS = ("evaluations/final/evidence.db", "sentinelx.db")


@dataclass(frozen=True)
class IntegrityRow:
    session_id: str
    source: str
    status: str  # OK | BROKEN | MISSING | NO_DB
    detail: str


@dataclass(frozen=True)
class IntegrityReport:
    built_at_utc: str
    db_path: str | None
    rows: list[IntegrityRow] = field(default_factory=list)
    note: str = "build-time check of stored evidence; not a live check"

    @property
    def ok_count(self) -> int:
        return sum(1 for r in self.rows if r.status == "OK")

    @property
    def failed(self) -> list[IntegrityRow]:
        return [r for r in self.rows if r.status not in ("OK",)]


def collect_session_ids(evaluations: Path) -> list[tuple[str, str]]:
    """(session_id, source) for every provenance.session_id referenced by a report."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    candidates = sorted(evaluations.glob("example_*/report.json"))
    candidates += sorted(evaluations.glob("example_scan_report/*/report.json"))
    for path in candidates:
        try:
            prov = _read_json(path).get("provenance") or {}
        except (OSError, ValueError):
            continue
        sid = prov.get("session_id")
        if isinstance(sid, str) and sid and sid not in seen:
            seen.add(sid)
            out.append((sid, path.as_posix()))
    return out


def _resolve_db(db_path: Path | None) -> Path | None:
    if db_path is not None:
        return db_path if db_path.is_file() else None
    for candidate in CANDIDATE_DBS:
        p = Path(candidate)
        if p.is_file():
            return p
    return None


def check_integrity(evaluations: Path, db_path: Path | None = None) -> IntegrityReport:
    refs = collect_session_ids(evaluations)
    db = _resolve_db(db_path)
    rows: list[IntegrityRow] = []
    if db is None:
        for sid, source in refs:
            rows.append(IntegrityRow(sid, source, "NO_DB",
                                     "no evidence database found in this worktree"))
        return IntegrityReport(datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), None, rows)

    conn = connect(Path(db))
    store = EvidenceStore(conn)
    for sid, source in refs:
        count = conn.execute("SELECT COUNT(*) FROM events WHERE session_id = ?",
                             (sid,)).fetchone()[0]
        if count == 0:
            rows.append(IntegrityRow(sid, source, "MISSING",
                                     "no events for this session in the evidence DB"))
            continue
        verification = store.verify_chain(sid)
        if verification.ok:
            rows.append(IntegrityRow(sid, source, "OK",
                                     f"{verification.events_checked} events verified"))
        else:
            rows.append(IntegrityRow(
                sid, source, "BROKEN",
                f"{verification.status.value}: first broken event "
                f"{verification.first_broken_event_id} ({verification.detail})"))
    conn.close()
    return IntegrityReport(datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), db.as_posix(),
                           rows)
