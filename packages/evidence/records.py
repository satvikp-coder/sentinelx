"""Insert/get for the non-event tables. Every write is validated by its Pydantic model and
redacted first. There is deliberately no update or delete here (sessions change state only
through ``sentinelx.evidence.sessions``)."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, TypeVar

from sentinelx.common_schemas import (
    ActionRequest,
    ApprovalRecord,
    AuditRecord,
    ContainmentBranch,
    EscalationTicket,
    IncidentFinding,
    PatchProposal,
    RepairVerification,
    ScanFinding,
    ScenarioSpec,
    SessionRecord,
    ShieldRule,
    SXModel,
    TargetAuthorization,
    UsageRecord,
    VerifierResult,
    format_utc,
)
from sentinelx.policy.redaction import redact

M = TypeVar("M", bound=SXModel)


@dataclass(frozen=True)
class _Spec:
    table: str
    id_field: str | None  # None = autoincrement id
    columns: dict[str, str]  # extra column -> model attribute ("" = taken from insert kwargs)
    constants: dict[str, str] = field(default_factory=dict)


_SPECS: dict[type[SXModel], _Spec] = {
    ScenarioSpec: _Spec("scenarios", "id", {}),
    TargetAuthorization: _Spec("targets", "target_id", {}),
    ActionRequest: _Spec("actions", "action_id", {"session_id": "session_id", "step": "step"}),
    IncidentFinding: _Spec("incidents", "incident_id", {"session_id": ""}),
    ContainmentBranch: _Spec(
        "branches", "branch_id", {"parent_session_id": "parent_session_id"}
    ),
    ScanFinding: _Spec("scan_findings", "id", {"target_id": "target_id"}),
    PatchProposal: _Spec("patches", "id", {"finding_id": "finding_id"}),
    RepairVerification: _Spec(
        "verifications", None, {"patch_id": "patch_id"}, {"kind": "REPAIR"}
    ),
    VerifierResult: _Spec(
        "verifications", None, {"session_id": "session_id"}, {"kind": "RUN"}
    ),
    ShieldRule: _Spec("shield_rules", "id", {"target_id": "target_id"}),
    EscalationTicket: _Spec("escalations", "id", {"finding_id": "finding_id"}),
    ApprovalRecord: _Spec(
        "approvals", "id", {"subject_type": "subject_type", "subject_id": "subject_id"}
    ),
}

# Tables with flat columns instead of a JSON body.
_USAGE_COLS = (
    "session_id", "provider", "model", "tokens_in", "tokens_out", "latency_ms",
    "estimated_cost", "error", "timestamp",
)
_AUDIT_COLS = (
    "session_id", "actor_id", "actor_role", "action", "from_state", "to_state", "timestamp",
    "detail",
)


def _validated(model: SXModel) -> dict[str, Any]:
    """Re-validate (catches model_construct bypasses), redact, return JSON-safe dict."""
    clean = type(model).model_validate_json(model.model_dump_json())
    return redact(json.loads(clean.model_dump_json())).value


class RecordStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def insert(self, model: SXModel, **extra: str) -> None:
        if isinstance(model, SessionRecord):
            return self._insert_session(model)
        if isinstance(model, UsageRecord | AuditRecord):
            return self._insert_flat(model)
        spec = _SPECS.get(type(model))
        if spec is None:
            raise TypeError(f"no table for {type(model).__name__}")
        body = _validated(model)
        cols: dict[str, Any] = {}
        for col, attr in spec.columns.items():
            cols[col] = extra[col] if attr == "" else body[attr]
        if spec.id_field is not None:
            cols["id"] = body[spec.id_field]
        if spec.table in {"scenarios", "targets"}:
            cols["created_at"] = format_utc(_now())
        cols.update(spec.constants)
        cols["body"] = json.dumps(body, sort_keys=True)
        names = ", ".join(cols)
        marks = ", ".join("?" for _ in cols)
        self.conn.execute(
            f"INSERT INTO {spec.table} ({names}) VALUES ({marks})",  # noqa: S608 (static names)
            list(cols.values()),
        )

    def get(self, model_cls: type[M], record_id: str) -> M | None:
        if model_cls is SessionRecord:
            row = self.conn.execute("SELECT * FROM sessions WHERE id = ?", (record_id,)).fetchone()
            return None if row is None else row_to_session(row)  # type: ignore[return-value]
        spec = _SPECS.get(model_cls)
        if spec is None or spec.id_field is None:
            raise TypeError(f"get() unsupported for {model_cls.__name__}")
        row = self.conn.execute(
            f"SELECT body FROM {spec.table} WHERE id = ?",  # noqa: S608 (static names)
            (record_id,),
        ).fetchone()
        return None if row is None else model_cls.model_validate_json(row["body"])

    # -- flat tables -------------------------------------------------------------------
    def _insert_session(self, s: SessionRecord) -> None:
        d = _validated(s)
        self.conn.execute(
            "INSERT INTO sessions (id, kind, scenario_id, target_id, arm, state, model, provider,"
            " created_at, started_at, ended_at, policy_version, fixture_version, idempotency_key,"
            " schema_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [d[k] for k in (
                "id", "kind", "scenario_id", "target_id", "arm", "state", "model", "provider",
                "created_at", "started_at", "ended_at", "policy_version", "fixture_version",
                "idempotency_key", "schema_version",
            )],
        )

    def _insert_flat(self, model: UsageRecord | AuditRecord) -> None:
        d = _validated(model)
        cols = _USAGE_COLS if isinstance(model, UsageRecord) else _AUDIT_COLS
        if "actor_role" in d:
            d["actor_role"] = str(d["actor_role"])
        table = "usage" if isinstance(model, UsageRecord) else "audit"
        self.conn.execute(
            f"INSERT INTO {table} ({', '.join(cols)}) "  # noqa: S608 (static names)
            f"VALUES ({', '.join('?' for _ in cols)})",
            [d[c] for c in cols],
        )


def _now() -> datetime:
    return datetime.now(UTC)


def row_to_session(row: sqlite3.Row) -> SessionRecord:
    return SessionRecord.model_validate({k: row[k] for k in row.keys()})

