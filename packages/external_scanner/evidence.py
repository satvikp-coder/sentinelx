"""Separate evidence storage for external scanner results."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ExternalFinding:
    """A finding from an external scanner, pending independent verification."""

    scanner_name: str
    scanner_version: str | None
    finding_id: str
    title: str
    description: str
    severity: str
    target: str
    evidence: dict[str, Any]
    imported_at: str
    confirmed: bool = False
    confirmation_reason: str | None = None


class ExternalEvidenceStore:
    """Separate SQLite store for external scanner findings."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS external_findings ("
            "id TEXT PRIMARY KEY, "
            "scanner_name TEXT NOT NULL, "
            "scanner_version TEXT, "
            "title TEXT NOT NULL, "
            "description TEXT, "
            "severity TEXT, "
            "target TEXT NOT NULL, "
            "evidence TEXT NOT NULL, "
            "imported_at TEXT NOT NULL, "
            "confirmed INTEGER NOT NULL DEFAULT 0, "
            "confirmation_reason TEXT)"
        )
        self._conn.commit()

    def add_finding(self, finding: ExternalFinding) -> None:
        """Add a finding to the store (unconfirmed by default)."""
        self._conn.execute(
            "INSERT INTO external_findings "
            "(id, scanner_name, scanner_version, title, description, "
            "severity, target, evidence, imported_at, confirmed, "
            "confirmation_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.finding_id,
                finding.scanner_name,
                finding.scanner_version,
                finding.title,
                finding.description,
                finding.severity,
                finding.target,
                json.dumps(finding.evidence),
                finding.imported_at,
                1 if finding.confirmed else 0,
                finding.confirmation_reason,
            ),
        )
        self._conn.commit()

    def list_findings(self, confirmed_only: bool = False) -> list[ExternalFinding]:
        """List all findings, optionally filtered by confirmation status."""
        if confirmed_only:
            rows = self._conn.execute(
                "SELECT * FROM external_findings WHERE confirmed = 1"
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT * FROM external_findings").fetchall()
        return [self._row_to_finding(row) for row in rows]

    def confirm_finding(self, finding_id: str, reason: str) -> None:
        """Mark a finding as confirmed (after independent Sentinel verification)."""
        self._conn.execute(
            "UPDATE external_findings SET confirmed = 1, confirmation_reason = ? WHERE id = ?",
            (reason, finding_id),
        )
        self._conn.commit()

    def _row_to_finding(self, row: tuple) -> ExternalFinding:
        return ExternalFinding(
            scanner_name=row[1],
            scanner_version=row[2],
            finding_id=row[0],
            title=row[3],
            description=row[4] or "",
            severity=row[5] or "unknown",
            target=row[6],
            evidence=json.loads(row[7]),
            imported_at=row[8],
            confirmed=bool(row[9]),
            confirmation_reason=row[10],
        )

    def close(self) -> None:
        self._conn.close()
