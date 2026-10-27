"""Paired experiment runner: arm A (no gateway) vs arm B (static least-privilege policy).

Why a new package (sentinelx.evaluation) rather than sentinelx.verifier.experiments: the
verifier must stay independent of the planner and the runtime (a test enforces it), while the
runner necessarily drives both. Metrics still use only verifier output and evidence.

Design points
* The manifest is immutable and hashed; the runner refuses to run if its hash does not match the
  recorded one (or the run header's, or ``expected_hash``). The hash goes into every report.
* Pairing: A and B of a case use the same seed (hence the same fixture reset and fixture_hash),
  the same planner and the same step / time budgets. Order across cases and arms is shuffled with
  the manifest's fixed ``order_seed`` and recorded in the run header, so it is reproducible.
* Crashed / failed runs are recorded as INVALID with a reason, excluded from rates, counted and
  reported. One retry is allowed for infrastructure errors only, and is flagged.
* Arm "C" (EVCS containment, Prompt 7) is a seam only: plug a runner into ``ARM_REGISTRY``.
"""

from __future__ import annotations

import json
import random
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinelx.agent_runtime import RunConfig, ScriptedNaivePlanner, run_session_sync
from sentinelx.common_schemas import Arm, SessionState
from sentinelx.evidence.db import connect, migrate
from sentinelx.evidence.store import EvidenceStore
from sentinelx.policy import LoadedPolicy, load_policy
from sentinelx.verifier import VERIFIER_VERSION

from .cases import FIXTURES, Case
from .manifest import (
    REPO_ROOT,
    Manifest,
    ManifestError,
    ManifestHashMismatch,
    RunHeaderMismatch,
    load_manifest,
    verify_fixtures,
)
from .records import PLANNER_LABEL, PlannerInfo, RunRecord, block_rules_from_events, to_jsonable
from .report import build_report, git_info, write_report

# arm label -> runtime arm. Arm "C" (EVCS containment, Prompt 7) will register here.
ARM_REGISTRY: dict[str, Arm] = {"A": Arm.UNPROTECTED, "B": Arm.PROTECTED}


@dataclass(frozen=True)
class PlannedRun:
    case_id: str
    arm: str
    rep: int
    order_index: int


@dataclass
class ExperimentResult:
    run_dir: Path
    manifest: Manifest
    records: list[RunRecord]
    report: dict[str, Any]
    report_paths: list[Path]


def plan_runs(manifest: Manifest, repetitions: int | None = None) -> list[PlannedRun]:
    """Every (case, arm, repetition), in an order shuffled by the manifest's fixed seed."""
    reps = repetitions or manifest.repetitions
    items = sorted((c.case_id, arm, rep) for rep in range(reps) for c in manifest.cases
                   for arm in manifest.arms)
    random.Random(manifest.order_seed).shuffle(items)
    return [PlannedRun(cid, arm, rep, i) for i, (cid, arm, rep) in enumerate(items)]


# ------------------------------------------------------------------ run header
def write_header(run_dir: Path, manifest: Manifest, run_id: str, order: list[PlannedRun],
                 policy: LoadedPolicy, repetitions: int) -> dict[str, Any]:
    header = {
        "run_id": run_id, "manifest_hash": manifest.manifest_hash,
        "manifest_name": manifest.name, "policy_version": policy.policy_version,
        "verifier_version": VERIFIER_VERSION, "order_seed": manifest.order_seed,
        "repetitions": repetitions, "planner": PLANNER_LABEL, "model": "none",
        "started_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "git": git_info(),
        "order": [[p.case_id, p.arm, p.rep] for p in order],
    }
    (run_dir / "header.json").write_text(json.dumps(header, indent=2) + "\n", encoding="utf-8",
                                         newline="\n")
    return header


def read_header(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "header.json").read_text(encoding="utf-8"))


def verify_header(run_dir: Path, manifest: Manifest) -> dict[str, Any]:
    header = read_header(run_dir)
    if header.get("manifest_hash") != manifest.manifest_hash:
        raise RunHeaderMismatch(
            f"run header records manifest {str(header.get('manifest_hash'))[:12]} but the manifest "
            f"is {manifest.manifest_hash[:12]}")
    return header


# ------------------------------------------------------------------ one run
def _leaked_processes(before: set[int]) -> int | None:
    try:
        import psutil
    except ImportError:
        return None
    return len([p for p in psutil.Process().children(recursive=True) if p.pid not in before])


def _children() -> set[int]:
    try:
        import psutil
    except ImportError:
        return set()
    return {p.pid for p in psutil.Process().children(recursive=True)}


def execute_run(conn: Any, lab: Any, policy: LoadedPolicy, manifest: Manifest, case: Case,
                planned: PlannedRun, run_id: str,
                runner: Callable[..., Any] = run_session_sync) -> RunRecord:
    """Run one (case, arm, rep). Never raises; failures become an INVALID record."""
    budgets = manifest.budgets
    before = _children()
    retried, first_error = False, None
    attempt = 0
    while True:
        attempt += 1
        started = datetime.now(UTC)
        result, error = None, None
        try:
            planner = ScriptedNaivePlanner(case.id, lab.port, task=case.template.task)
            config = RunConfig(arm=ARM_REGISTRY[planned.arm], seed=case.template.seed,
                               max_steps=budgets.max_steps,
                               wall_clock_seconds=budgets.wall_clock_seconds,
                               op_timeout=budgets.op_timeout)
            result = runner(conn, lab, case.scenario, planner, config, policy)
        except Exception as exc:  # infrastructure failure before/while running
            error = f"{type(exc).__name__}: {str(exc)[:200]}"
        infra = error is not None or (result is not None and result.abort_reason == "RUNTIME_ERROR")
        if infra and attempt == 1:  # one retry, for infrastructure errors only, flagged
            retried, first_error = True, error or "RUNTIME_ERROR"
            continue
        break
    ended = datetime.now(UTC)
    base: dict[str, Any] = dict(
        run_id=run_id, case_id=case.id, arm=planned.arm, rep=planned.rep, label=case.label,
        scenario=case.template.family, surface=case.template.surface.value,
        order_index=planned.order_index, seed=case.template.seed, retried=retried,
        first_attempt_error=first_error,
        planner=PlannerInfo(name=ScriptedNaivePlanner.name, kind=ScriptedNaivePlanner.kind),
        started_at=started.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        ended_at=ended.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        leaked_processes=_leaked_processes(before),
    )
    if result is None:
        return RunRecord(**base, valid=False, invalid_reason=f"exception: {error}")
    events = EvidenceStore(conn).list_session(result.session_id)
    chain_ok = EvidenceStore(conn).verify_chain(result.session_id).ok
    reason = None
    if result.state is not SessionState.COMPLETED:
        reason = f"state {result.state.value}: {result.abort_reason}"
    elif result.verifier is None:
        reason = "verifier did not run"
    elif not chain_ok:
        reason = "evidence chain failed verification"
    return RunRecord(
        **base, session_id=result.session_id, valid=reason is None, invalid_reason=reason,
        fixture_hash=result.fixture_hash, policy_version=result.policy_version,
        verifier_version=result.verifier.verifier_version if result.verifier else None,
        total_ms=result.total_ms, gateway_decision_ms=result.gateway_decision_ms,
        page_policy_ms=result.page_policy_ms, end_state=result.state.value,
        abort_reason=result.abort_reason, chain_ok=chain_ok, verifier=result.verifier,
        block_rules=block_rules_from_events(events),
    )


# ------------------------------------------------------------------ the experiment
def run_experiment(
    manifest_path: str | Path, out_root: str | Path, *, repetitions: int | None = None,
    run_id: str | None = None, run_dir: str | Path | None = None, expected_hash: str | None = None,
    fixtures: Path = FIXTURES, write: bool = True, progress: Callable[[str], None] | None = None,
    runner: Callable[..., Any] = run_session_sync,
) -> ExperimentResult:
    from apps.fixture_lab.server import LabServer  # the lab is an app, imported lazily

    manifest = load_manifest(manifest_path, fixtures=fixtures)  # verifies hash, cases, policy
    if expected_hash is not None and expected_hash != manifest.manifest_hash:
        raise ManifestHashMismatch(
            f"expected manifest hash {expected_hash[:12]} but the manifest is "
            f"{manifest.manifest_hash[:12]}")
    cases = verify_fixtures(manifest, fixtures)
    policy = load_policy(REPO_ROOT / manifest.policy_file)
    reps = repetitions or manifest.repetitions
    order = plan_runs(manifest, reps)

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    rid = run_id or f"run-{stamp}-{manifest.manifest_hash[:8]}"
    d = Path(run_dir) if run_dir is not None else Path(out_root) / rid
    if (d / "header.json").exists():
        verify_header(d, manifest)  # raises RunHeaderMismatch if the recorded hash differs
        if (d / "runs.jsonl").exists() and (d / "runs.jsonl").read_text(encoding="utf-8").strip():
            raise ManifestError(f"run directory {d} already holds results; use a new run id")
    d.mkdir(parents=True, exist_ok=True)
    write_header(d, manifest, rid, order, policy, reps)

    records: list[RunRecord] = []
    lab = LabServer(Path(tempfile.mkdtemp(prefix="sx-ledger-", dir=d)))
    conn = connect(d / "evidence.db")
    migrate(conn)
    try:
        lab.start()
        with (d / "runs.jsonl").open("a", encoding="utf-8", newline="\n") as out:
            for planned in order:
                record = execute_run(conn, lab, policy, manifest, cases[planned.case_id], planned,
                                     rid, runner)
                records.append(record)
                out.write(json.dumps(to_jsonable(record), sort_keys=True) + "\n")
                out.flush()
                if progress:
                    progress(f"[{planned.order_index + 1}/{len(order)}] {record.case_id} "
                             f"arm {record.arm} rep {record.rep}: "
                             f"{'ok' if record.valid else 'INVALID ' + str(record.invalid_reason)}")
    finally:
        lab.stop()
        conn.close()
    report = build_report(records, manifest, rid)
    paths = write_report(report, d) if write else []
    return ExperimentResult(d, manifest, records, report, paths)


def load_records(run_dir: Path) -> list[RunRecord]:
    lines = (run_dir / "runs.jsonl").read_text(encoding="utf-8").splitlines()
    return [RunRecord.model_validate_json(line) for line in lines if line.strip()]


def regenerate_report(run_dir: str | Path, manifest_path: str | Path,
                      fixtures: Path = FIXTURES) -> dict[str, Any]:
    """Rebuild the report from raw run records; refuses if the manifest differs from the header."""
    d = Path(run_dir)
    manifest = load_manifest(manifest_path, fixtures=fixtures)
    header = verify_header(d, manifest)
    report = build_report(load_records(d), manifest, header["run_id"])
    write_report(report, d)
    return report
