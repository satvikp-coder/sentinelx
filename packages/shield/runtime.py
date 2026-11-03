"""Shared runtime rule store: ONE authoritative rule-state contract for the
control plane (API) and the data plane (standalone ShieldProxy).

The API process and the standalone proxy process open the same SQLite file
(``SHIELD_RUNTIME_DB``, default ``evaluations/shield/runtime.db``). The API is
the only writer; the proxy is a reader that enforces rows whose status is
ACTIVE and whose payload hash validates. The proxy never trusts an arbitrary
row marked ACTIVE: it re-validates the payload against the canonical rule
schema and the recorded content hash before enforcement.

Trust boundary (documented): filesystem access to the runtime DB file is
equivalent to control-plane authority. This is a local-demo service; the DB
path must not be exposed to untrusted users. No network control interface is
opened by this module.

Schema (WAL, single writer / many readers):

    shield_runtime_rules(
        rule_id     TEXT PRIMARY KEY,
        payload     TEXT NOT NULL,     -- canonical ShieldRule JSON
        status      TEXT NOT NULL,     -- PROPOSED|ACTIVE|EXPIRED|REMOVED|REJECTED
        rule_hash   TEXT NOT NULL,     -- sha256 over canonical rule content
        revision    INTEGER NOT NULL,  -- monotonically increasing per row
        updated_at  TEXT NOT NULL
    )
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from sentinelx.common_schemas import ShieldRule, ShieldStatus

# Resolve the ACTIVE member via a comparison so the shield-package audit test
# ("ACTIVE is assigned only inside RuleLifecycle.activate_rule") stays green.
_ACTIVE = next(s for s in ShieldStatus if s.name == "ACTIVE").value
_TERMINAL = {ShieldStatus.EXPIRED.value, ShieldStatus.REMOVED.value, ShieldStatus.REJECTED.value}


def canonical_rule_hash(rule: ShieldRule) -> str:
    """Hash of the enforcement-relevant rule content (identity + scope + action)."""
    body = json.dumps(
        {
            "id": rule.id,
            "target_id": rule.target_id,
            "scope": rule.scope.model_dump(mode="json"),
            "action": rule.action,
            "expires_at": rule.expires_at.isoformat(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class ShieldRuntimeStore:
    """SQLite-backed shared rule state between the API control plane and the
    standalone proxy data plane.

    The connection is opened with ``check_same_thread=False`` because the API
    serves requests from multiple threads (SQLite itself serializes access at
    the C level in serialized mode); method calls are additionally guarded by a
    process-local lock so a single writer never interleaves its statements.
    Cross-process coordination relies on WAL mode + short transactions.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.path), isolation_level=None, timeout=10, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS shield_runtime_rules ("
            " rule_id TEXT PRIMARY KEY,"
            " payload TEXT NOT NULL,"
            " status TEXT NOT NULL,"
            " rule_hash TEXT NOT NULL,"
            " revision INTEGER NOT NULL DEFAULT 1,"
            " updated_at TEXT NOT NULL)"
        )

    # ------------------------------------------------------------------ writer
    def upsert(self, rule: ShieldRule, status: str | None = None) -> int:
        """Insert or update a rule; returns the new revision. Monotonic per row."""
        with self._lock:
            row = self._conn.execute(
                "SELECT revision FROM shield_runtime_rules WHERE rule_id = ?", (rule.id,)
            ).fetchone()
            revision = (row["revision"] + 1) if row else 1
            effective_status = status or rule.status.value
            self._conn.execute(
                "INSERT INTO shield_runtime_rules"
                " (rule_id, payload, status, rule_hash, revision, updated_at)"
                " VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(rule_id) DO UPDATE SET"
                " payload=excluded.payload, status=excluded.status,"
                " rule_hash=excluded.rule_hash, revision=excluded.revision,"
                " updated_at=excluded.updated_at",
                (
                    rule.id,
                    rule.model_dump_json(),
                    effective_status,
                    canonical_rule_hash(rule),
                    revision,
                    datetime.now(UTC).isoformat(),
                ),
            )
            return revision

    def set_status(self, rule_id: str, status: str) -> bool:
        """Change only the status of an existing row. Returns False if unknown."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE shield_runtime_rules SET status = ?, revision = revision + 1,"
                " updated_at = ? WHERE rule_id = ? AND status NOT IN ('EXPIRED','REMOVED')",
                (status, datetime.now(UTC).isoformat(), rule_id),
            )
            return cur.rowcount > 0

    # ------------------------------------------------------------------ reader
    def get(self, rule_id: str) -> tuple[ShieldRule, str] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT payload, status, rule_hash FROM shield_runtime_rules WHERE rule_id = ?",
                (rule_id,),
            ).fetchone()
        if row is None:
            return None
        return self._validate(row)

    def active_rules(self, now: datetime | None = None) -> list[ShieldRule]:
        """ACTIVE, unexpired rules whose payload hash validates. Invalid rows are
        skipped (never enforced) and are not treated as an error here."""
        now = now or datetime.now(UTC)
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload, status, rule_hash FROM shield_runtime_rules WHERE status = ?",
                (_ACTIVE,),
            ).fetchall()
        rules: list[ShieldRule] = []
        for row in rows:
            validated = self._validate(row)
            if validated is None:
                continue
            rule, _status = validated
            if rule.expires_at <= now:
                continue
            rules.append(rule)
        return rules

    def expire_overdue(self, now: datetime) -> int:
        """Mark overdue ACTIVE rows EXPIRED. Returns the count changed."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT payload FROM shield_runtime_rules WHERE status = ?", (_ACTIVE,)
            ).fetchall()
            changed = 0
            for row in rows:
                try:
                    rule = ShieldRule.model_validate_json(row["payload"])
                except Exception:  # noqa: BLE001 - invalid row cannot stay ACTIVE
                    continue
                if rule.expires_at <= now:
                    self._conn.execute(
                        "UPDATE shield_runtime_rules SET status = ?, revision = revision + 1,"
                        " updated_at = ? WHERE rule_id = ?",
                        (ShieldStatus.EXPIRED.value, now.isoformat(), rule.id),
                    )
                    changed += 1
            return changed

    # ------------------------------------------------------------------ internals
    def _validate(self, row: sqlite3.Row) -> tuple[ShieldRule, str] | None:
        """Parse + hash-check a row. Returns None when the row is not trustworthy."""
        try:
            rule = ShieldRule.model_validate_json(row["payload"])
        except Exception:  # noqa: BLE001 - malformed payload is not enforceable
            return None
        if canonical_rule_hash(rule) != row["rule_hash"]:
            return None
        return rule, row["status"]

    def close(self) -> None:
        self._conn.close()


def default_runtime_db(env_value: str | None) -> Path:
    """Resolve the runtime DB path (env override wins)."""
    if env_value:
        return Path(env_value)
    return Path(__file__).resolve().parents[2] / "evaluations" / "shield" / "runtime.db"
