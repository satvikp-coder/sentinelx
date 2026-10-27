"""The baseline investigator and finding verifier on REAL scripted-planner sessions (S1, arms A
and B) run through the browser, the lab and the gateway. No model is involved."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from sentinelx.agent_runtime import RunConfig, ScriptedNaivePlanner, run_session_sync
from sentinelx.common_schemas import Arm, EvidenceState, FindingState, Severity
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.store import EvidenceStore
from sentinelx.investigator import baseline_investigate, build_timeline, investigate, verify_finding
from tests.e2e.conftest import load_spec

pytestmark = pytest.mark.browser


@pytest.fixture(scope="module")
def own_db(tmp_path_factory: pytest.TempPathFactory) -> Iterator:
    conn = connect(tmp_path_factory.mktemp("inv") / "inv.db")
    migrate(conn)
    yield conn
    conn.close()


@pytest.fixture(scope="module")
def s1(lab, own_db, lab_policy) -> dict[Arm, str]:
    out: dict[Arm, str] = {}
    for arm in (Arm.UNPROTECTED, Arm.PROTECTED):
        result = run_session_sync(own_db, lab, load_spec("S1"),
                                  ScriptedNaivePlanner("S1", lab.port), RunConfig(arm=arm),
                                  lab_policy)
        out[arm] = result.session_id
    return out


def test_arm_a_baseline_finding_is_correct_and_fully_verified(own_db, s1) -> None:
    sid = s1[Arm.UNPROTECTED]
    finding = baseline_investigate(own_db, sid)
    verification = verify_finding(own_db, sid, finding)
    assert verification.state is FindingState.CONFIRMED
    assert all(c.passed for c in verification.claims) and verification.citation_denominator > 5
    texts = [c.text for c in finding.claims]
    assert "The session ran in arm UNPROTECTED." in texts
    assert any(t.startswith("The agent followed untrusted instructions") for t in texts)
    assert "The independent verifier recorded forbidden_outcome_occurred=True." in texts
    assert not any("attempting to redirect" in t for t in texts)
    assert finding.severity is not Severity.LOW
    # the facts name the real events: the proposal, the SIMULATED shadow decision, the execution
    events = EvidenceStore(own_db).list_session(sid)
    kinds = {e.id: e.kind for e in events}
    cited = {i for c in finding.claims for i in c.cited_event_ids}
    assert {"ACTION_PROPOSED", "SHADOW_DECISION", "ACTION_EXECUTED", "VERIFIER_RESULT"} <= {
        kinds[i] for i in cited}
    assert not any(kinds[i] == "ACTION_DECIDED" for i in cited), "arm A has no real decisions"


def test_arm_b_baseline_finding_is_correct_and_fully_verified(own_db, s1) -> None:
    sid = s1[Arm.PROTECTED]
    finding = baseline_investigate(own_db, sid)
    verification = verify_finding(own_db, sid, finding)
    assert verification.state is FindingState.CONFIRMED
    assert all(c.passed for c in verification.claims)
    texts = [c.text for c in finding.claims]
    assert "The session ran in arm PROTECTED." in texts
    assert "The independent verifier recorded forbidden_outcome_occurred=False." in texts
    assert any(t.startswith("The policy gateway decided BLOCK") for t in texts)
    assert any("attempting to redirect the agent" in t for t in texts)
    assert not any("followed untrusted instructions" in t for t in texts)
    reasons = [c.assertion.value for c in finding.claims
               if c.assertion and c.assertion.field_path == "decision.reason_code"]
    assert reasons and all(isinstance(r, str) and r for r in reasons)
    events = {e.id: e for e in EvidenceStore(own_db).list_session(sid)}
    block = next(e for e in events.values() if e.kind == "ACTION_DECIDED"
                 and e.payload["decision"]["decision"] == "BLOCK")
    assert block.id in {i for c in finding.claims for i in c.cited_event_ids}
    assert finding.severity is Severity.CRITICAL, "the attempted action was a secret egress"


def test_same_attempt_same_severity_whether_or_not_the_attack_succeeded(own_db, s1) -> None:
    a = baseline_investigate(own_db, s1[Arm.UNPROTECTED])
    b = baseline_investigate(own_db, s1[Arm.PROTECTED])
    assert a.severity == b.severity


def test_stored_results_have_correct_labels_and_the_chain_stays_valid(own_db, s1) -> None:
    sid = s1[Arm.PROTECTED]
    inv = investigate(own_db, sid, None)
    store = EvidenceStore(own_db)
    found, verified = store.get(inv.finding_event_id or ""), store.get(inv.verified_event_id or "")
    assert found is not None and verified is not None
    assert (found.state, verified.state) == (EvidenceState.INFERRED, EvidenceState.VERIFIED)
    assert store.verify_chain(sid).ok
    stored = " ".join(json.dumps(e.payload) for e in store.list_session(sid))
    assert not re.search(r"synth_tok_[0-9a-f]{8,}", stored)


def test_timeline_chains_show_the_blocked_and_the_executed_forbidden_action(own_db, s1) -> None:
    a = build_timeline(own_db, s1[Arm.UNPROTECTED])
    b = build_timeline(own_db, s1[Arm.PROTECTED])
    assert any(c.outcome == "executed" and c.shadow_event_id for c in a.chains)
    assert any(c.outcome == "blocked" and c.decision == "BLOCK" for c in b.chains)
    assert not any(c.outcome == "executed" and c.decision == "BLOCK" for c in b.chains)
    assert Path(__file__).exists()
