"""Manifest hashing, drift detection, run order, run-header refusal and invalid-run bookkeeping.
No browser needed: the run loop is replaced by fake runners where a run is needed."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinelx.agent_runtime import RunResult
from sentinelx.common_schemas import (
    Actor,
    ActorRole,
    Arm,
    SessionKind,
    SessionState,
    VerifierResult,
)
from sentinelx.evaluation.cases import FIXTURES, load_all_cases, payload_path
from sentinelx.evaluation.manifest import (
    REPO_ROOT,
    Budgets,
    Manifest,
    ManifestDriftError,
    ManifestError,
    ManifestHashMismatch,
    RunHeaderMismatch,
    build_manifest,
    compute_manifest_hash,
    load_manifest,
    seal,
    write_manifest,
)
from sentinelx.evaluation.runner import (
    PlannedRun,
    execute_run,
    plan_runs,
    regenerate_report,
    run_experiment,
)
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.sessions import SessionService
from sentinelx.policy import load_policy

COMMITTED = REPO_ROOT / "evaluations" / "manifest.json"


@pytest.fixture()
def fixtures_copy(tmp_path: Path) -> Path:
    root = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, root)
    return root


def small_manifest(fixtures: Path = FIXTURES, **kw) -> Manifest:
    kw.setdefault("case_ids", ["A01", "B01", "A02", "B02"])
    return build_manifest(name="t", order_seed=kw.pop("order_seed", 5), fixtures=fixtures, **kw)


# ------------------------------------------------------------------ hash
def test_manifest_hash_is_deterministic_and_content_sensitive() -> None:
    a, b = small_manifest(), small_manifest()
    assert a.manifest_hash == b.manifest_hash == compute_manifest_hash(a)
    assert len(a.manifest_hash) == 64
    assert small_manifest(order_seed=6).manifest_hash != a.manifest_hash
    assert small_manifest(repetitions=2).manifest_hash != a.manifest_hash
    assert small_manifest(case_ids=["A01", "B01"]).manifest_hash != a.manifest_hash
    assert small_manifest(budgets=Budgets(max_steps=7)).manifest_hash != a.manifest_hash
    edited = a.model_copy(update={"cases": [a.cases[0].model_copy(update={"seed": 99}),
                                            *a.cases[1:]]})
    assert compute_manifest_hash(edited) != a.manifest_hash


def test_editing_a_sealed_manifest_file_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(small_manifest(), path)
    assert load_manifest(path).manifest_hash
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["cases"][0]["seed"] += 1
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ManifestHashMismatch):
        load_manifest(path)
    doc["cases"][0]["seed"] -= 1
    doc["manifest_hash"] = ""
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ManifestHashMismatch):  # an unsealed manifest is not runnable
        load_manifest(path)


def test_changing_a_case_after_sealing_is_detected(fixtures_copy: Path, tmp_path: Path) -> None:
    m = small_manifest(fixtures_copy)
    path = tmp_path / "m.json"
    write_manifest(m, path)
    assert load_manifest(path, fixtures=fixtures_copy).manifest_hash == m.manifest_hash
    payload = payload_path(load_all_cases(fixtures_copy)[0].template, fixtures_copy)
    payload.write_text(payload.read_text(encoding="utf-8") + "<!-- tweak -->\n", encoding="utf-8")
    with pytest.raises(ManifestDriftError):
        load_manifest(path, fixtures=fixtures_copy)


def test_changing_a_case_template_after_sealing_is_detected(fixtures_copy: Path,
                                                            tmp_path: Path) -> None:
    m = small_manifest(fixtures_copy)
    path = tmp_path / "m.json"
    write_manifest(m, path)
    case_file = fixtures_copy / "benign" / "B01.json"
    doc = json.loads(case_file.read_text(encoding="utf-8"))
    doc["notes"] += " (edited)"
    case_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    with pytest.raises(ManifestDriftError):
        load_manifest(path, fixtures=fixtures_copy)
    (fixtures_copy / "benign" / "B01.json").unlink()
    with pytest.raises(ManifestDriftError):
        load_manifest(path, fixtures=fixtures_copy)


def test_policy_changes_after_sealing_are_detected(tmp_path: Path) -> None:
    m = small_manifest()
    stale = seal(m.model_copy(update={"policy_version": "lab@000000000000"}))
    path = tmp_path / "m.json"
    write_manifest(stale, path)
    with pytest.raises(ManifestDriftError):
        load_manifest(path)


def test_the_reserved_third_arm_is_not_accepted() -> None:
    with pytest.raises(ValueError):
        Manifest.model_validate({**small_manifest().model_dump(), "arms": ["A", "C"]})


def test_the_committed_manifest_is_valid_and_matches_the_fixtures() -> None:
    m = load_manifest(COMMITTED)
    assert m.manifest_hash == compute_manifest_hash(m)
    assert sum(c.label == "attack" for c in m.cases) >= 12
    assert sum(c.label == "benign" for c in m.cases) >= 12
    assert m.arms == ["A", "B"] and m.planner == "scripted-naive"
    assert {c.case_id for c in m.cases} == {c.id for c in load_all_cases()}


# ------------------------------------------------------------------ order
def test_run_order_is_reproducible_from_the_recorded_seed() -> None:
    m = small_manifest()
    assert plan_runs(m) == plan_runs(m)
    assert plan_runs(m) != plan_runs(small_manifest(order_seed=999))
    full = load_manifest(COMMITTED)
    order = plan_runs(full)
    assert order == plan_runs(full)
    assert [p.order_index for p in order] == list(range(len(order)))
    keys = [(p.case_id, p.arm, p.rep) for p in order]
    assert len(keys) == len(set(keys)) == len(full.cases) * 2
    assert keys != sorted(keys), "the order must actually be randomised"
    arms_in_first_pairs = [p.arm for p in order[:6]]
    assert set(arms_in_first_pairs) == {"A", "B"}, "arms are interleaved, not blocked"


def test_repetitions_multiply_the_plan() -> None:
    m = small_manifest()
    assert len(plan_runs(m, 3)) == 3 * len(plan_runs(m, 1))
    assert {p.rep for p in plan_runs(m, 3)} == {0, 1, 2}


# ------------------------------------------------------------------ refusals
def test_runner_refuses_when_the_run_header_records_a_different_hash(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(small_manifest(), path)
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    (run_dir / "header.json").write_text(json.dumps({"manifest_hash": "ab" * 32}), encoding="utf-8")
    with pytest.raises(RunHeaderMismatch):
        run_experiment(path, tmp_path / "runs", run_dir=run_dir)
    assert not (run_dir / "runs.jsonl").exists(), "nothing may run after a refusal"


def test_runner_refuses_an_unexpected_manifest_hash(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(small_manifest(), path)
    with pytest.raises(ManifestHashMismatch):
        run_experiment(path, tmp_path / "runs", expected_hash="cd" * 32)
    assert not (tmp_path / "runs").exists()


def test_runner_refuses_an_unsealed_or_edited_manifest(tmp_path: Path) -> None:
    path = tmp_path / "m.json"
    write_manifest(small_manifest(), path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["order_seed"] = 123456
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ManifestHashMismatch):
        run_experiment(path, tmp_path / "runs")
    assert not (tmp_path / "runs").exists()


def test_runner_refuses_to_add_to_a_run_directory_that_already_has_results(tmp_path: Path) -> None:
    m = small_manifest()
    path = tmp_path / "m.json"
    write_manifest(m, path)
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    (run_dir / "header.json").write_text(json.dumps({"manifest_hash": m.manifest_hash}),
                                         encoding="utf-8")
    (run_dir / "runs.jsonl").write_text('{"x": 1}\n', encoding="utf-8")
    with pytest.raises(ManifestError):
        run_experiment(path, tmp_path / "runs", run_dir=run_dir)


def test_regenerating_a_report_requires_the_same_manifest(tmp_path: Path) -> None:
    run_dir = tmp_path / "r"
    run_dir.mkdir()
    (run_dir / "header.json").write_text(json.dumps({"manifest_hash": "ef" * 32, "run_id": "r"}),
                                         encoding="utf-8")
    path = tmp_path / "m.json"
    write_manifest(small_manifest(), path)
    with pytest.raises(RunHeaderMismatch):
        regenerate_report(run_dir, path)


# ------------------------------------------------------------------ invalid-run bookkeeping
@pytest.fixture()
def env(tmp_path: Path):
    conn = connect(tmp_path / "e.db")
    migrate(conn)
    manifest = small_manifest()
    case = next(c for c in load_all_cases() if c.id == "A01")
    policy = load_policy(REPO_ROOT / manifest.policy_file)
    lab = SimpleNamespace(port=12345)
    return conn, manifest, case, policy, lab, SessionService(conn)


def planned(arm: str = "B") -> PlannedRun:
    return PlannedRun("A01", arm, 0, 0)


def fake_result(svc: SessionService, state=SessionState.COMPLETED, abort=None, verifier=True):
    actor = Actor(id="t", role=ActorRole.SYSTEM)
    s, _ = svc.create(SessionKind.AGENT_RUN, "lab@x", actor)
    v = VerifierResult(session_id=s.id, scenario_id="A01", verifier_version="1.1.0",
                       forbidden_outcome_occurred=False, goal_met=True, attempted_forbidden=True,
                       executed_forbidden=False, blocked_forbidden=True, false_blocks=0,
                       stopped_by=["TOOL_NOT_IN_SCENARIO"])
    return RunResult(s.id, "A01", Arm.PROTECTED, state, abort, "answer", "f" * 64, "lab@x",
                     v if verifier else None, 3, gateway_decision_ms=[0.1, 0.2],
                     page_policy_ms=[0.05], total_ms=12.0, boundaries=("sandbox",))


def test_a_crashed_run_is_recorded_invalid_after_one_flagged_retry(env) -> None:
    conn, manifest, case, policy, lab, _ = env
    calls = []

    def boom(*a, **k):
        calls.append(1)
        raise RuntimeError("browser exploded")

    rec = execute_run(conn, lab, policy, manifest, case, planned(), "r", boom)
    assert len(calls) == 2, "exactly one retry for an infrastructure error"
    assert rec.valid is False and rec.retried is True
    assert rec.invalid_reason.startswith("exception: RuntimeError")
    assert rec.first_attempt_error and rec.verifier is None and rec.session_id is None


def test_an_infrastructure_error_that_recovers_is_valid_but_flagged(env) -> None:
    conn, manifest, case, policy, lab, svc = env
    calls = []

    def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("transient")
        return fake_result(svc)

    rec = execute_run(conn, lab, policy, manifest, case, planned(), "r", flaky)
    assert rec.valid and rec.retried and "OSError" in (rec.first_attempt_error or "")
    assert rec.verifier and rec.chain_ok is True and rec.gateway_decision_ms == [0.1, 0.2]
    assert rec.planner.label == "SIMULATED scripted"
    assert (rec.provider, rec.model) == ("none", "none")


@pytest.mark.parametrize(("state", "abort", "expect"), [
    (SessionState.FAILED, "MAX_STEPS", "state FAILED: MAX_STEPS"),
    (SessionState.FAILED, "WALL_CLOCK_TIMEOUT", "state FAILED: WALL_CLOCK_TIMEOUT"),
    (SessionState.CANCELLED, "KILL_SWITCH", "state CANCELLED: KILL_SWITCH"),
])
def test_failed_runs_are_invalid_without_retry(env, state, abort, expect) -> None:
    conn, manifest, case, policy, lab, svc = env
    calls = []

    def runner(*a, **k):
        calls.append(1)
        return fake_result(svc, state, abort)

    rec = execute_run(conn, lab, policy, manifest, case, planned(), "r", runner)
    assert len(calls) == 1 and rec.valid is False and rec.retried is False
    assert rec.invalid_reason == expect


def test_a_runtime_error_state_is_retried_once_as_an_infrastructure_error(env) -> None:
    conn, manifest, case, policy, lab, svc = env
    calls = []

    def runner(*a, **k):
        calls.append(1)
        return fake_result(svc, SessionState.FAILED, "RUNTIME_ERROR")

    rec = execute_run(conn, lab, policy, manifest, case, planned(), "r", runner)
    assert len(calls) == 2 and rec.retried and not rec.valid
    assert rec.invalid_reason == "state FAILED: RUNTIME_ERROR"


def test_a_run_without_a_verifier_result_is_invalid(env) -> None:
    conn, manifest, case, policy, lab, svc = env
    rec = execute_run(conn, lab, policy, manifest, case, planned(), "r",
                      lambda *a, **k: fake_result(svc, verifier=False))
    assert not rec.valid and rec.invalid_reason == "verifier did not run"


def test_a_broken_evidence_chain_makes_a_run_invalid(env) -> None:
    conn, manifest, case, policy, lab, svc = env
    result = fake_result(svc)
    conn.execute("UPDATE events SET payload = '{\"tampered\": true}' WHERE session_id = ?",
                 (result.session_id,))
    rec = execute_run(conn, lab, policy, manifest, case, planned(), "r", lambda *a, **k: result)
    assert not rec.valid and rec.invalid_reason == "evidence chain failed verification"
    assert rec.chain_ok is False
