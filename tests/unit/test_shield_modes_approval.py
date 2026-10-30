"""Recommend / enforce modes, human approval, gate-token activation, ACTIVE-assignment audit."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinelx.common_schemas import (
    ApprovalDecision,
    ApprovalRecord,
    EvidenceState,
    ShieldStatus,
)
from sentinelx.shield.config import ShieldConfig
from sentinelx.shield.recorder import hash_client_key
from sentinelx.shield.rules import (
    BenignReplayGate,
    GateError,
    GateResult,
    ShieldAction,
)
from sentinelx.shield.server import build_app

ROOT = Path(__file__).resolve().parents[2]
KEY = hash_client_key("attacker")
BENIGN_NOTES = [{"method": "GET", "path": "/api/notes/1", "params": {}, "headers": {}}]


def make(mode: str, auto: bool = False, benign: list[dict] | None = None):
    cfg = ShieldConfig(upstream="http://127.0.0.1:1", mode=mode, auto_shield=auto, lab_mode=True)
    app = build_app(cfg, benign)
    p = app.proxy
    eid = p.store.append(p.session_id, "shield_intent", EvidenceState.INFERRED, "t",
                         {"intent": "RECON"}).id
    return p, eid


def approval(rule_id: str, decision: ApprovalDecision = ApprovalDecision.APPROVE
             ) -> ApprovalRecord:
    return ApprovalRecord(id="appr_t1", subject_type="shield_rule", subject_id=rule_id,
                          reviewer="human", decision=decision, rationale="ok",
                          timestamp=datetime.now(UTC))


def statuses(p) -> list[ShieldStatus]:
    return [r.status for r in p.rules.list_rules()]


def test_monitor_never_proposes() -> None:
    p, eid = make("monitor")
    p._consider_rule(KEY, "RECON", "/.env", {}, eid)
    assert p.rules.list_rules() == [] and p.counts["proposed"] == 0


def test_recommend_stores_proposed_and_tickets_never_activates() -> None:
    p, eid = make("recommend", benign=BENIGN_NOTES)
    p._consider_rule(KEY, "RECON", "/.env", {}, eid)
    p._consider_rule(KEY, "DATA_ENUMERATION", "/api/notes/4", {}, eid)  # benign uses it
    assert statuses(p) == [ShieldStatus.PROPOSED]
    assert p.counts["activated"] == 0 and p.counts["escalations"] == 1
    assert len(p.tickets) == 1
    kinds = [e.kind for e in p.store.list_session(p.session_id)]
    assert "shield_gate" in kinds and "shield_escalation" in kinds


def test_enforce_without_auto_waits_for_approval_and_regates() -> None:
    p, eid = make("enforce", auto=False, benign=BENIGN_NOTES)
    p._consider_rule(KEY, "RECON", "/.env", {}, eid)
    rule = p.rules.list_rules()[0]
    assert rule.status == ShieldStatus.PROPOSED
    result = p.approve_rule(rule.id, approval(rule.id))
    assert result.passed and p.rules.get_rule(rule.id).status == ShieldStatus.ACTIVE


def test_approval_is_rejected_when_rule_would_now_block_benign() -> None:
    p, eid = make("enforce", auto=False, benign=[])
    p._consider_rule(KEY, "RECON", "/.env", {}, eid)
    rule = p.rules.list_rules()[0]
    p._benign = [{"method": "GET", "path": "/.env", "params": {}, "headers": {}}]  # traffic changed
    result = p.approve_rule(rule.id, approval(rule.id))
    assert not result.passed
    assert p.rules.get_rule(rule.id).status == ShieldStatus.PROPOSED
    assert p.counts["escalations"] == 1


def test_wrong_or_reject_approval_raises() -> None:
    p, eid = make("enforce")
    p._consider_rule(KEY, "RECON", "/.env", {}, eid)
    rule = p.rules.list_rules()[0]
    with pytest.raises(GateError):
        p.approve_rule(rule.id, approval(rule.id, ApprovalDecision.REJECT))
    with pytest.raises(GateError):
        p.approve_rule(rule.id, approval("other_rule"))


def test_enforce_auto_activates_after_gate() -> None:
    p, eid = make("enforce", auto=True)
    p._consider_rule(KEY, "RECON", "/.env", {}, eid)
    assert statuses(p) == [ShieldStatus.ACTIVE]


def _proposed(p, eid):
    p._consider_rule(KEY, "RECON", "/.env", {}, eid)
    rule = p.rules.list_rules()[0]
    return rule, p._gate_for(rule).check(rule)


def test_activate_requires_valid_gate_result() -> None:
    p, eid = make("recommend")
    rule, good = _proposed(p, eid)
    lc = p.rules
    other = BenignReplayGate(p.store, p.session_id, []).check(
        p._compiler.compile(eid, ShieldAction.BLOCK_ROUTE_PATTERN,
                            rule.scope.model_copy(update={"route": "/.git"}), "r", "o",
                            intent_event_ids=[eid]).rule)
    failed = GateResult(False, 1, 1, [], None, good.rule_hash, good.checked_at)
    stale = GateResult(True, 0, 0, [], None, good.rule_hash,
                       datetime.now(UTC) - timedelta(minutes=10))
    for bad in (None, failed, stale, other):
        with pytest.raises(GateError):
            lc.activate_rule(rule.id, bad)
    assert lc.get_rule(rule.id).status == ShieldStatus.PROPOSED
    assert lc.activate_rule(rule.id, good) is True


def test_active_is_assigned_only_inside_activate_rule() -> None:
    offenders = []
    for path in [*(ROOT / "packages" / "shield").rglob("*.py"), *(ROOT / "scripts").rglob("*.py")]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}

        def enclosing(node, parents=parents):
            while node in parents:
                node = parents[node]
                if isinstance(node, ast.FunctionDef):
                    return node.name
            return None

        for node in ast.walk(tree):
            is_active = (isinstance(node, ast.Attribute) and node.attr == "ACTIVE"
                         and isinstance(node.value, ast.Name) and node.value.id == "ShieldStatus")
            is_str = isinstance(node, ast.Constant) and node.value == "ACTIVE"
            if (is_active or is_str) and not isinstance(parents.get(node), ast.Compare):
                if enclosing(node) != "activate_rule":
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    # the evaluator's "assume_active" check is a comparison; everything else must be absent
    assert offenders == [], offenders
