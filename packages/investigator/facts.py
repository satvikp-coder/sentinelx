"""Structured facts from a session's evidence. Deterministic: no model, no network.

A fact is a short, bounded description of ONE evidence event plus the ``fields`` (dotted payload
paths -> scalar values) that a claim may assert about it. Only fields from an allowlist per event
kind are exposed, so long free text (page excerpts, request bodies) never travels whole."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from sentinelx.common_schemas import EvidenceEvent
from sentinelx.evidence.store import EvidenceStore

VERIFIER_EVENT = "VERIFIER_RESULT"
FIELD_LIMIT = 120  # characters of any single string value that is exposed
SCALARS = (str, int, float, bool, type(None))

# event kind -> payload keys exposed as facts (dotted paths are flattened from these roots)
EXPOSED: dict[str, tuple[str, ...]] = {
    "RUN_STARTED": ("arm", "scenario_id", "protected", "policy_version", "policy_mode",
                    "attack_surface", "planner"),
    "ACTION_PROPOSED": ("tool", "step", "action_id", "arguments"),
    "ACTION_DECIDED": ("decision",),
    "SHADOW_DECISION": ("decision",),
    "ACTION_EXECUTED": ("tool", "action_id", "arm", "ok", "status", "final_url", "error",
                        "sandbox_blocked"),
    "EGRESS_BLOCKED": ("url", "source_url", "resource_type", "method", "channel", "reason",
                       "rule_ids", "policy_version", "boundary"),
    "SANDBOX_BLOCKED": ("url", "resource_type", "channel", "reason", "boundary"),
    "OBSERVATION_RECORDED": ("source", "url", "action_id", "text_length", "excerpt", "untrusted"),
    VERIFIER_EVENT: ("result",),
    "RUN_FINISHED": ("end_state", "abort_reason", "steps", "arm", "final_answer"),
    "PLANNER_FAILED": ("reason",),
}
# values from these payload roots came from pages / the agent and are untrusted text
UNTRUSTED_ROOTS = {"excerpt", "arguments", "final_answer", "url", "source_url"}
# inside the verifier result only these flat keys are exposed
VERIFIER_KEYS = ("verifier_version", "forbidden_outcome_occurred", "goal_met",
                 "attempted_forbidden", "executed_forbidden", "blocked_forbidden",
                 "false_blocks", "stopped_by", "cited_event_ids")


@dataclass(frozen=True)
class Fact:
    fact_id: str
    kind: str  # the event kind it describes
    event_id: str
    seq: int
    state: str  # evidence state of the event (OBSERVED, SIMULATED, ...)
    fields: dict[str, Any] = field(default_factory=dict)
    untrusted: tuple[str, ...] = ()  # field paths whose text came from a page / the agent
    parent_event_id: str | None = None


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > FIELD_LIMIT:
        return value[:FIELD_LIMIT] + "…[truncated]"
    return value


def flatten(value: Any, prefix: str, out: dict[str, Any], depth: int = 0) -> None:
    """Scalars and short lists/dicts -> dotted paths (lists use indexes, depth is bounded)."""
    if isinstance(value, SCALARS):
        out[prefix] = _clip(value)
    elif depth >= 3:
        return
    elif isinstance(value, dict):
        for k in sorted(value):
            flatten(value[k], f"{prefix}.{k}", out, depth + 1)
    elif isinstance(value, list):
        for i, item in enumerate(value[:6]):
            flatten(item, f"{prefix}.{i}", out, depth + 1)


def fact_for(event: EvidenceEvent, index: int) -> Fact | None:
    roots = EXPOSED.get(event.kind)
    if roots is None:
        return None
    fields: dict[str, Any] = {}
    for root in roots:
        if root not in event.payload:
            continue
        if event.kind == VERIFIER_EVENT:
            result = event.payload[root]
            if isinstance(result, dict):
                for key in VERIFIER_KEYS:
                    if key in result:
                        flatten(result[key], f"result.{key}", fields)
            continue
        flatten(event.payload[root], root, fields)
    untrusted = tuple(p for p in fields if p.split(".")[0] in UNTRUSTED_ROOTS)
    return Fact(f"F{index}", event.kind, event.id, event.seq, event.state.value, fields, untrusted,
                event.parent_event_id)


def build_facts(conn: sqlite3.Connection, session_id: str) -> list[Fact]:
    """The ordered facts of one session (empty if the session has no evidence)."""
    facts: list[Fact] = []
    for event in EvidenceStore(conn).list_session(session_id):
        fact = fact_for(event, len(facts) + 1)
        if fact is not None:
            facts.append(fact)
    return facts


def verifier_fields(facts: list[Fact]) -> dict[str, Any]:
    """The verifier's flat result fields, or {} if the session has no VERIFIER_RESULT."""
    for fact in facts:
        if fact.kind == VERIFIER_EVENT:
            return {k.removeprefix("result."): v for k, v in fact.fields.items()}
    return {}
