"""Coverage ledger: rows = (check, endpoint); columns = exercised, persona, evidence event ids,
and a reason when skipped (profile excludes it, not applicable, or a budget/rate/kill-switch stop
happened before the check's turn). The scan never silently claims to have checked more than it
did: every applicable cell appears, whether or not it produced a finding."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .checks import CATALOG
from .context import ScanContext
from .models import Candidate


class CoverageRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str
    endpoint: str
    exercised: bool
    persona: str | None = None
    evidence_event_ids: list[str] = []
    reason: str | None = None


class CoverageLedger(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rows: list[CoverageRow]

    @property
    def coverage_percent(self) -> float:
        if not self.rows:
            return 100.0
        return round(100.0 * sum(r.exercised for r in self.rows) / len(self.rows), 2)

    @property
    def unexercised(self) -> list[CoverageRow]:
        return [r for r in self.rows if not r.exercised]


def _persona_for(ep: str, candidates: list[Candidate]) -> str | None:
    hit = next((c for c in candidates if ep in c.endpoints), None)
    return hit.persona if hit else None


def build_ledger(ctx: ScanContext, profile_checks: list[str], candidates: list[Candidate],
                 skipped_checks: dict[str, str]) -> CoverageLedger:
    """`skipped_checks`: check_id -> reason, for checks the orchestrator never ran at all
    (a budget/rate/kill-switch stop that happened before that check's turn)."""
    rows: list[CoverageRow] = []
    for check_id, check in CATALOG.items():
        if check_id not in profile_checks:
            rows.append(CoverageRow(check_id=check_id, endpoint="(all)", exercised=False,
                                    reason="profile excludes this check"))
            continue
        if check_id in skipped_checks:
            try:
                universe = check.applicable(ctx)
            except Exception:  # noqa: BLE001 - coverage must never crash the report
                universe = []
            for ep in universe or ["(all)"]:
                rows.append(CoverageRow(check_id=check_id, endpoint=ep, exercised=False,
                                        reason=skipped_checks[check_id]))
            continue
        try:
            universe = check.applicable(ctx)
        except Exception:  # noqa: BLE001
            universe = []
        if not universe:
            rows.append(CoverageRow(check_id=check_id, endpoint="(none)", exercised=False,
                                    reason="not applicable: no matching endpoint was found"))
            continue
        own = [c for c in candidates if c.check_id == check_id]
        for ep in universe:
            event_ids = [e for c in own if ep in c.endpoints for e in c.evidence_event_ids]
            rows.append(CoverageRow(check_id=check_id, endpoint=ep, exercised=True,
                                    persona=_persona_for(ep, own), evidence_event_ids=event_ids))
    return CoverageLedger(rows=rows)
