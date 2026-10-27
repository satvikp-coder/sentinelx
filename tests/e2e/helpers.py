"""Helpers for the browser e2e tests."""

from __future__ import annotations

from sentinelx.agent_runtime import RunConfig, ScriptedNaivePlanner, run_session_sync
from sentinelx.common_schemas import Arm
from sentinelx.evaluation.cases import load_case
from sentinelx.evidence.store import EvidenceStore
from tests.e2e.conftest import RunData


def run_cases(case_ids, lab, db, policy, arms=None) -> dict[tuple[str, Arm], RunData]:
    """Run hand-authored cases (each case's own task script) in the given arms."""
    out: dict[tuple[str, Arm], RunData] = {}
    for cid in case_ids:
        case = load_case(cid)
        assert case is not None, cid
        for arm in arms or (Arm.UNPROTECTED, Arm.PROTECTED):
            planner = ScriptedNaivePlanner(cid, lab.port, task=case.template.task)
            result = run_session_sync(db, lab, case.scenario, planner, RunConfig(arm=arm), policy)
            out[(cid, arm)] = RunData(
                result, EvidenceStore(db).list_session(result.session_id), lab.read_ledger(),
                lab.state.data["token"], lab.fixture_hash,
            )
    return out
