"""Safe results import for external scanner findings.

External scanner results are imported into Sentinel's evidence store
without automatic confirmation. They require independent verification.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .evidence import ExternalEvidenceStore, ExternalFinding


def import_external_results(
    store: ExternalEvidenceStore,
    scanner_name: str,
    scanner_version: str | None,
    results: list[dict[str, Any]],
) -> list[str]:
    """Import external scanner results into the evidence store.

    Returns a list of imported finding IDs. All findings are imported
    as unconfirmed (confirmed=False) pending independent verification.
    """
    imported_ids: list[str] = []
    for result in results:
        finding = ExternalFinding(
            scanner_name=scanner_name,
            scanner_version=scanner_version,
            finding_id=result.get("finding_id", "unknown"),
            title=result.get("title", ""),
            description=result.get("description", ""),
            severity=result.get("severity", "unknown"),
            target=result.get("target", ""),
            evidence=result.get("evidence", {}),
            imported_at=datetime.now(UTC).isoformat(),
            confirmed=False,
        )
        store.add_finding(finding)
        imported_ids.append(finding.finding_id)
    return imported_ids
