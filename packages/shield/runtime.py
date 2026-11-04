"""Durable local Shield authority, with atomic lifecycle evidence.

The API is the sole control-plane writer. Proxies read the same private SQLite
file. Filesystem write permission is control-plane authority: checksums detect
corruption, not malicious privileged writers. ACTIVE publication and its evidence
commit in ONE database transaction, so process death cannot expose half a commit.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    ApprovalRecord,
    EvidenceState,
    SessionKind,
    ShieldRule,
    ShieldStatus,
)
from sentinelx.evidence.db import migrate, transaction
from sentinelx.evidence.sessions import SessionService
from sentinelx.evidence.store import EvidenceStore
from sentinelx.policy.redaction import redact

_SESSION = "shield-runtime-v2"
_ACTIVE = next(s for s in ShieldStatus if s.name == "ACTIVE").value
_TERMINAL = {"EXPIRED", "REMOVED", "REJECTED"}


def target_identity(upstream: str) -> str:
    """Operator-configured upstream namespace; not a client-selected target."""
    return "shield:" + hashlib.sha256(upstream.rstrip("/").encode()).hexdigest()[:32]


def canonical_rule_hash(rule: ShieldRule) -> str:
    """Versioned enforcement digest. Legacy hashes fail closed and need reapproval."""
    body = json.dumps({
        "version": 2, "id": rule.id, "target_id": rule.target_id,
        "scope": rule.scope.model_dump(mode="json"), "action": rule.action,
        "mode": rule.mode.value, "expires_at": rule.expires_at.isoformat(),
    }, sort_keys=True, separators=(",", ":"))
    return "v2:" + hashlib.sha256(body.encode()).hexdigest()


class ShieldRuntimeStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), isolation_level=None, timeout=2, check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS shield_runtime_rules ("
            "rule_id TEXT PRIMARY KEY,payload TEXT NOT NULL,status TEXT NOT NULL,"
            "rule_hash TEXT NOT NULL,revision INTEGER NOT NULL,updated_at TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS shield_runtime_approvals ("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT,session_id TEXT NOT NULL,"
            "subject_id TEXT NOT NULL,payload TEXT NOT NULL)"
        )
        migrate(self._conn)
        with self._lock, transaction(self._conn):
            if self._conn.execute("SELECT id FROM sessions WHERE id=?", (_SESSION,)).fetchone() \
                    is None:
                SessionService(self._conn).create(
                    SessionKind.GUARD, "shield-runtime-2",
                    Actor(id="shield-control-plane", role=ActorRole.SYSTEM), session_id=_SESSION,
                )
        self.evidence = EvidenceStore(self._conn)

    def _append_event(self, kind: str, payload: dict[str, Any]) -> Any:
        return self.evidence.append(
            _SESSION, kind, EvidenceState.OBSERVED, "sentinelx.shield", payload,
        )

    def upsert(self, rule: ShieldRule, status: str | None = None) -> int:
        """Trusted writer primitive. API activations must use publish_activation()."""
        clean = rule.model_copy(update={
            "reason": str(redact(rule.reason).value), "owner": str(redact(rule.owner).value),
        })
        with self._lock, transaction(self._conn):
            row = self._conn.execute(
                "SELECT revision FROM shield_runtime_rules WHERE rule_id=?", (rule.id,),
            ).fetchone()
            revision = row[0] + 1 if row else 1
            self._conn.execute(
                "INSERT INTO shield_runtime_rules VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(rule_id) DO UPDATE SET payload=excluded.payload,"
                "status=excluded.status,rule_hash=excluded.rule_hash,"
                "revision=excluded.revision,updated_at=excluded.updated_at",
                (clean.id, clean.model_dump_json(), status or clean.status.value,
                 canonical_rule_hash(clean), revision, datetime.now(UTC).isoformat()),
            )
            if row is None and (status or clean.status.value) == "PROPOSED":
                self._append_event("SHIELD_RULE_PROPOSED", {
                    "rule_id": clean.id, "target_id": clean.target_id,
                    "enforcement_hash": canonical_rule_hash(clean), "mode": clean.mode.value,
                    "expires_at": clean.expires_at.isoformat(),
                })
            return revision

    def record_approval(self, session_id: str, record: ApprovalRecord) -> int:
        with self._lock, transaction(self._conn):
            clean = redact(record.model_dump(mode="json")).value
            cursor = self._conn.execute(
                "INSERT INTO shield_runtime_approvals(session_id,subject_id,payload) VALUES(?,?,?)",
                (session_id, record.subject_id, json.dumps(clean)),
            )
            seq = int(cursor.lastrowid)
            self._append_event("SHIELD_APPROVAL_RECORDED", {
                "session_id": session_id, "subject_id": record.subject_id,
                "approval_id": record.id, "decision": record.decision.value, "sequence": seq,
            })
            return seq

    def latest_approval(self, session_id: str, subject: str) -> tuple[ApprovalRecord, int] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT seq,payload FROM shield_runtime_approvals "
                "WHERE session_id=? AND subject_id=? ORDER BY seq DESC LIMIT 1",
                (session_id, subject),
            ).fetchone()
        return None if row is None else (ApprovalRecord.model_validate_json(row[1]), row[0])

    def publish_activation(
        self, rule: ShieldRule, *, session_id: str, subject: str, approval_seq: int,
        gate_hash: str,
    ) -> int:
        """Publish rule and required activation evidence together, or neither.

        Recheck revocation inside the same writer transaction as publication.
        The staging lifecycle is not the served proxy lifecycle.
        """
        with self._lock, transaction(self._conn):
            latest = self.latest_approval(session_id, subject)
            if latest is None or latest[1] != approval_seq or latest[0].decision.value != "approve":
                raise ValueError("approval changed before activation")
            existing = self.get(rule.id)
            if existing is None or existing[1] != "PROPOSED":
                raise ValueError("rule is not a durable proposal")
            if canonical_rule_hash(existing[0]) != canonical_rule_hash(rule):
                raise ValueError("proposal changed before activation")
            revision = self.upsert(rule, status=_ACTIVE)
            self._append_event("SHIELD_RULE_ACTIVATED", {
                "rule_id": rule.id, "target_id": rule.target_id, "rule_hash": gate_hash,
                "enforcement_hash": canonical_rule_hash(rule), "revision": revision,
                "approval_id": latest[0].id, "approval_subject": subject,
                "approval_sequence": approval_seq, "session_id": session_id,
            })
            return revision

    def set_status(self, rule_id: str, status: str) -> bool:
        if status not in {s.value for s in ShieldStatus}:
            raise ValueError("unknown rule status")
        with self._lock, transaction(self._conn):
            current = self.get(rule_id)
            if current is None:
                return False
            if current[1] in _TERMINAL:
                return True  # already inert; never revive a terminal rule
            self._conn.execute(
                "UPDATE shield_runtime_rules SET status=?,revision=revision+1,updated_at=? "
                "WHERE rule_id=?", (status, datetime.now(UTC).isoformat(), rule_id),
            )
            self._append_event("SHIELD_RULE_" + status, {"rule_id": rule_id, "state": status})
            return True

    def get(self, rule_id: str) -> tuple[ShieldRule, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT rule_id,payload,status,rule_hash FROM shield_runtime_rules WHERE rule_id=?",
                (rule_id,),
            ).fetchone()
        return None if row is None else self._validate(row)

    def all_rules(self) -> list[tuple[ShieldRule, str]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT rule_id,payload,status,rule_hash FROM shield_runtime_rules ORDER BY rowid"
            ).fetchall()
        return [value for row in rows if (value := self._validate(row)) is not None]

    def active_rules(self, now: datetime | None = None) -> list[ShieldRule]:
        now = now or datetime.now(UTC)
        return [r for r, status in self.all_rules() if status == _ACTIVE and r.expires_at > now]

    def expire_overdue(self, now: datetime) -> int:
        with self._lock, transaction(self._conn):
            overdue = [r.id for r, s in self.all_rules() if s == _ACTIVE and r.expires_at <= now]
            for rid in overdue:
                self.set_status(rid, "EXPIRED")
            return len(overdue)

    def _validate(self, row: sqlite3.Row) -> tuple[ShieldRule, str] | None:
        try:
            rule = ShieldRule.model_validate_json(row["payload"])
            status = ShieldStatus(row["status"])
            if row["rule_id"] != rule.id or canonical_rule_hash(rule) != row["rule_hash"]:
                return None
        except (ValueError, TypeError):
            return None
        return rule.model_copy(update={"status": status}), status.value

    def close(self) -> None:
        self._conn.close()

    def audit(self, limit: int = 50) -> dict[str, Any]:
        """Read actual durable lifecycle evidence, not the ephemeral SSE buffer."""
        with self._lock:
            chain = self.evidence.verify_chain(_SESSION)
            events = self.evidence.list_session(_SESSION)
            return {
                "session_id": _SESSION, "ok": chain.ok,
                "chain_status": chain.status.value, "events_checked": chain.events_checked,
                "events": [e.model_dump(mode="json") for e in events[-limit:]],
            }


def default_runtime_db(env_value: str | None) -> Path:
    if env_value:
        return Path(env_value)
    return Path(__file__).resolve().parents[2] / "evaluations" / "shield" / "runtime.db"
